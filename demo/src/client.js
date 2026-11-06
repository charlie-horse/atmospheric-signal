// One atsignal user with one device. Publishes keys as repo records, sends
// libsignal ciphertext as is.neuros.atsignal.message records, and finds
// incoming messages through the tag indexer.
import * as S from '@signalapp/libsignal-client'
import * as cbor from '@ipld/dag-cbor'
import { randomBytes, randomInt } from 'node:crypto'
import { lex, NS } from './lexicons.js'
import { Stores } from './stores.js'
import { firstContactTag, pairTag, windowOf } from './tags.js'

const FORMAT = 1
const DEVICE_ID = 1
const T = (name) => `${NS}.defs#${name}`

function assertPlaintext(pt) {
  const r = lex.validate(`${NS}.defs#plaintext`, pt)
  if (!r.success) throw r.error
}
export function encodePlaintext(content) {
  const pt = { content }
  assertPlaintext(pt)
  return cbor.encode(pt)
}
export function decodePlaintext(bytes) {
  const pt = cbor.decode(bytes)
  assertPlaintext(pt)
  return pt.content
}

export class Client {
  constructor(name, did, { pds, indexer, clock, log }) {
    Object.assign(this, { name, did, pds, indexer, clock, log })
    this.contacts = new Map() // peerDid -> { tagSeed }
    this.seen = new Set()
    this.inbox = []
    this.alerts = []
    this.preKeyRkeys = new Map()
    this.addr = S.ProtocolAddress.new(did, DEVICE_ID)
    this.exts = [] // extensions (groups.js): extra content types, tags, hooks
  }

  // --- key publication (design doc §1) ---------------------------------
  async register(nPreKeys = 3) {
    const id = S.IdentityKeyPair.generate()
    this.identity = id
    this.registrationId = randomInt(1, 16380)
    this.stores = new Stores(id, this.registrationId, {
      // The owner deletes a one-time prekey record once it is used.
      onPreKeyRemoved: (pid) => {
        const rkey = this.preKeyRkeys.get(pid)
        if (rkey) this.pds.deleteRecord(this.did, `${NS}.preKey`, rkey)
        this.log(`${this.name} used one-time prekey ${pid}; deleted its record`)
      },
      onIdentityChanged: (did) => this.alerts.push(did),
    })
    this.pds.createAccount(this.did)
    const now = this.clock.now()

    this.pds.putRecord(this.did, `${NS}.identity`, 'self', {
      identityKey: id.publicKey.serialize(),
      formatVersion: FORMAT,
      createdAt: new Date(now).toISOString(),
    })

    const spk = S.PrivateKey.generate()
    const spkSig = id.privateKey.sign(spk.getPublicKey().serialize())
    await this.stores.signedPreKey.saveSignedPreKey(1, S.SignedPreKeyRecord.new(1, now, spk.getPublicKey(), spk, spkSig))

    const kyb = S.KEMKeyPair.generate()
    const kybSig = id.privateKey.sign(kyb.getPublicKey().serialize())
    await this.stores.kyberPreKey.saveKyberPreKey(1, S.KyberPreKeyRecord.new(1, now, kyb, kybSig))

    this.pds.putRecord(this.did, `${NS}.device`, randomBytes(8).toString('hex'), {
      deviceId: DEVICE_ID,
      registrationId: this.registrationId,
      signedPreKey: { keyId: 1, publicKey: spk.getPublicKey().serialize(), signature: spkSig },
      kyberPreKey: { keyId: 1, publicKey: kyb.getPublicKey().serialize(), signature: kybSig },
      formatVersion: FORMAT,
      createdAt: new Date(now).toISOString(),
    })

    for (let i = 1; i <= nPreKeys; i++) {
      const pk = S.PrivateKey.generate()
      await this.stores.preKey.savePreKey(i, S.PreKeyRecord.new(i, pk.getPublicKey(), pk))
      const { rkey } = this.pds.putRecord(this.did, `${NS}.preKey`, null, {
        deviceId: DEVICE_ID, preKeyId: i, publicKey: pk.getPublicKey().serialize(), formatVersion: FORMAT,
      })
      this.preKeyRkeys.set(i, rkey)
    }
    this.log(`${this.name} (${this.did}) published identity, 1 device, ${nPreKeys} one-time prekeys`)
  }

  // Read a peer's prekey bundle straight out of their public repo.
  // useOneTimePreKey=false skips the one-time prekey (see groups.js: concurrent
  // initiators to one peer race on the same prekey record).
  fetchBundle(peerDid, useOneTimePreKey = true) {
    const ident = this.pds.getRecord(peerDid, `${NS}.identity`, 'self')
    const [dev] = this.pds.listRecords(peerDid, `${NS}.device`)
    const [otk] = useOneTimePreKey ? this.pds.listRecords(peerDid, `${NS}.preKey`) : [] // may race (open question 11)
    const d = dev.value
    return S.PreKeyBundle.new(
      d.registrationId, d.deviceId,
      otk ? otk.value.preKeyId : null,
      otk ? S.PublicKey.deserialize(otk.value.publicKey) : null,
      d.signedPreKey.keyId, S.PublicKey.deserialize(d.signedPreKey.publicKey), d.signedPreKey.signature,
      S.PublicKey.deserialize(ident.identityKey),
      d.kyberPreKey.keyId, S.KEMPublicKey.deserialize(d.kyberPreKey.publicKey), d.kyberPreKey.signature,
    )
  }

  peerAddr(did) {
    // Sender device id is not in the message record (open question 8); use their only device.
    const [dev] = this.pds.listRecords(did, `${NS}.device`)
    return S.ProtocolAddress.new(did, dev.value.deviceId)
  }

  // --- pairwise messaging (design doc §2) ------------------------------
  async startConversation(peerDid, firstText, { useOneTimePreKey = true } = {}) {
    const peer = this.peerAddr(peerDid)
    await S.processPreKeyBundle(this.fetchBundle(peerDid, useOneTimePreKey), peer, this.addr, this.stores.session, this.stores.identityStore)
    const tagSeed = randomBytes(32)
    this.contacts.set(peerDid, { tagSeed })
    await this.#write(peerDid, firstContactTag(peerDid), 'firstContact', { $type: T('conversationInit'), tagSeed })
    if (firstText) await this.sendText(peerDid, firstText)
  }

  async sendText(peerDid, text) { return this.send(peerDid, { $type: T('text'), text }) }

  // Send any defs#plaintext content over the existing pairwise session.
  async send(peerDid, content) {
    const { tagSeed } = this.contacts.get(peerDid)
    const tag = pairTag(tagSeed, this.did, peerDid, windowOf(this.clock.now()))
    return this.#write(peerDid, tag, null, content)
  }

  async #write(peerDid, tag, forcedType, content) {
    const ct = await S.signalEncrypt(encodePlaintext(content), this.peerAddr(peerDid), this.addr,
      this.stores.session, this.stores.identityStore, new Date(this.clock.now()))
    const envelopeType = forcedType ?? (ct.type() === S.CiphertextMessageType.PreKey ? 'prekey' : 'whisper')
    const ref = this.pds.putRecord(this.did, `${NS}.message`, null, {
      tag, envelopeType, ciphertext: ct.serialize(), formatVersion: FORMAT,
    })
    this.seen.add(`${ref.did}/${ref.rkey}`)
    return ref
  }

  expectedTags() {
    const w = windowOf(this.clock.now())
    const tags = [firstContactTag(this.did)]
    for (const [peer, { tagSeed }] of this.contacts) for (const win of [w, w - 1]) tags.push(pairTag(tagSeed, peer, this.did, win))
    return tags
  }

  // Look up expected tags in the indexer, fetch each record from its
  // sender's repo, decrypt. Repeats because a first contact adds new tags.
  async poll() {
    let got = 0, more = true
    while (more) {
      more = false
      for (const tag of this.expectedTags()) {
        for (const ref of this.indexer.lookup(tag)) {
          const key = `${ref.did}/${ref.rkey}`
          if (this.seen.has(key)) continue
          this.seen.add(key)
          const rec = this.pds.getRecord(ref.did, ref.collection, ref.rkey)
          if (!rec) continue // sender deleted it
          const content = await this.#decrypt(ref.did, rec)
          got++
          if (content.$type === T('conversationInit')) {
            this.contacts.set(ref.did, { tagSeed: content.tagSeed })
            this.log(`${this.name} accepted first contact from ${ref.did}; now watching its pairwise tags`)
            for (const x of this.exts) await x.onNewContact?.(ref.did)
            more = true
          } else if (content.$type === T('text')) {
            this.inbox.push({ from: ref.did, text: content.text })
            this.log(`${this.name} <- ${ref.did}: "${content.text}"  [${rec.envelopeType}]`)
          } else {
            for (const x of this.exts) if (await x.onContent?.(ref.did, content)) more = true
          }
        }
      }
      for (const x of this.exts) got += await x.poll()
    }
    return got
  }

  async #decrypt(senderDid, rec) {
    const from = this.peerAddr(senderDid)
    const s = this.stores
    if (rec.envelopeType === 'firstContact' || rec.envelopeType === 'prekey') {
      return decodePlaintext(await S.signalDecryptPreKey(S.PreKeySignalMessage.deserialize(rec.ciphertext),
        from, this.addr, s.session, s.identityStore, s.preKey, s.signedPreKey, s.kyberPreKey))
    }
    if (rec.envelopeType === 'whisper') {
      return decodePlaintext(await S.signalDecrypt(S.SignalMessage.deserialize(rec.ciphertext),
        from, this.addr, s.session, s.identityStore))
    }
    throw new Error(`unhandled envelopeType ${rec.envelopeType}`)
  }

  safetyNumber(peerDid) {
    const peerKey = S.PublicKey.deserialize(this.pds.getRecord(peerDid, `${NS}.identity`, 'self').identityKey)
    return S.Fingerprint.new(5200, 2, Buffer.from(this.did), this.identity.publicKey, Buffer.from(peerDid), peerKey)
      .displayableFingerprint().toString()
  }
}
