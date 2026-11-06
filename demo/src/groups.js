// Groups (design doc §3, decision 4) on top of the pairwise Client.
//
// Lexicon gaps found (lexicons NOT edited; findings for the design doc):
//  G1. No plaintext def carries the group secrets a member needs: the group
//      tag seed (to find group messages) and the group-state key (to read the
//      groupState record), nor a pointer to where the groupState record lives
//      (creator DID + rkey; defs#recordRef exists but no payload uses it).
//      The demo carries them as `demo.gap#groupSecrets` (GAP below), a
//      demo-local type that is NOT in the lexicons.
//  G2. defs#plaintext's union is open (no `closed: true`), so lexicon
//      validation accepts any $type, even a non-NSID, and extra fields on
//      known defs. GAP only "validates" because of this; the union does not
//      enforce its five types.
//  G3. defs#text has no group context. A received group text cannot say which
//      group it belongs to; the demo infers it from the tag it was found by.
//  G4. groupChange.signature does not define its signing input. Demo: the
//      bytes "atsignal/groupChange/v1\0" + DAG-CBOR(change without
//      `signature`, $type included). The prefix separates these signatures
//      from libsignal's own uses of the identity key (prekey signatures).
//  G5. groupChange binds only `epoch`, not the prior state (no previous-state
//      hash). Two admins issuing epoch N+1 concurrently fork the group, and
//      each half rejects the other's later changes.
//  G6. senderKeyDistribution carries no epoch, so a receiver cannot tell a
//      stale SKDM from a current one. The demo checks membership at decrypt
//      time instead (repo DID must be a current member).
//  G7. groupSnapshot is unsigned and names no creator/signer; a joiner trusts
//      whoever handed it the state key. groupState is written only by the
//      creator, so it goes stale if a non-creator admin changes membership or
//      the creator is removed.
//  G8. groupAction has no self-removal ("leave"); a non-admin cannot leave.
//  G9. message.tag is described as a pairwise tag; group tags reuse it.
//
// Group tag scheme (OUR DESIGN, not spec):
//   tag = HMAC-SHA256(groupTagSeed, "atsignal/group/v1\0" + senderDid + "\0" + hourWindow)[:16]
// The seed is random per epoch and travels only inside pairwise ciphertext
// (GAP). Mixing in the sender DID gives each sender its own tag, so the
// indexer never sees the same tag in two repos (which would reveal that the
// two senders share a group). Members look up tags for every other member,
// for the current and previous window and the current and previous seed.
//
// Other demo rules (OUR DESIGN): a new tag seed and state key per epoch, sent
// by the signing admin to the remaining members; when two members lack a
// pairwise session, the one with the smaller DID starts it (the other waits
// and sends its SKDM on the conversationInit); an admin always starts a
// session with a joiner, since the joiner does not know the group yet.
import * as S from '@signalapp/libsignal-client'
import * as cbor from '@ipld/dag-cbor'
import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { lex, NS } from './lexicons.js'
import { encodePlaintext, decodePlaintext } from './client.js'
import { TAG_LEN, windowOf } from './tags.js'

const T = (n) => `${NS}.defs#${n}`
const GAP = 'demo.gap#groupSecrets' // NOT a lexicon type: see G1
const FORMAT = 1

export function groupTag(seed, senderDid, window) {
  return createHmac('sha256', seed).update(`atsignal/group/v1\0${senderDid}\0${window}`).digest().subarray(0, TAG_LEN)
}

const signingInput = ({ signature, ...rest }) =>
  Buffer.concat([Buffer.from('atsignal/groupChange/v1\0'), cbor.encode(rest)])
const stateAd = (gid, epoch) => Buffer.from(`atsignal/groupState/v1\0${gid}\0${epoch}`)
const rekeys = (actions) => actions.some((a) => a.action === 'addMember' || a.action === 'removeMember')

export class Groups {
  constructor(client) {
    this.c = client
    this.groups = new Map() // groupId -> state
    this.stash = new Map() // `${gid}/${epoch}` -> secrets that arrived before the change
    this.pending = new Map() // peerDid -> Set(gid): SKDM owed once a session exists
    client.exts.push(this)
  }
  get me() { return this.c.did }
  log(s) { this.c.log(`${this.c.name}: ${s}`) }

  // --- creation and the encrypted groupState record --------------------
  async create(title, others) {
    const gid = randomBytes(16).toString('base64url') // 22 chars, valid rkey
    const g = this.#init(gid, { epoch: 0, members: [this.me, ...others], admins: [this.me], title, creator: this.me })
    Object.assign(g, this.#newSecrets())
    this.#writeSnapshot(g)
    this.log(`created group ${gid} "${title}" with ${others.length} others; wrote encrypted groupState`)
    for (const m of others) await this.#connect(m, true)
    await this.#sendSecrets(g, others)
    await this.#rekey(g)
    return gid
  }

  #init(gid, s) {
    const g = { gid, ...s, inbox: [], rejected: [], failed: new Map(), removed: false }
    this.groups.set(gid, g)
    return g
  }
  #newSecrets() { return { stateKey: randomBytes(32), tagSeed: randomBytes(32) } }

  #writeSnapshot(g) {
    const snap = { $type: T('groupSnapshot'), groupId: g.gid, epoch: g.epoch, members: g.members, admins: g.admins, title: g.title }
    const nonce = randomBytes(12)
    const ct = S.Aes256GcmSiv.new(g.stateKey).encrypt(cbor.encode(snap), nonce, stateAd(g.gid, g.epoch))
    this.c.pds.putRecord(this.me, `${NS}.groupState`, g.gid, {
      epoch: g.epoch, stateCiphertext: Buffer.concat([nonce, ct]), formatVersion: FORMAT,
    })
  }

  #readSnapshot(creator, gid, epoch, stateKey) {
    const rec = this.c.pds.getRecord(creator, `${NS}.groupState`, gid)
    if (!rec || rec.epoch !== epoch) throw new Error(`groupState missing or at wrong epoch`)
    const ct = Buffer.from(rec.stateCiphertext)
    const snap = cbor.decode(S.Aes256GcmSiv.new(stateKey).decrypt(ct.subarray(12), ct.subarray(0, 12), stateAd(gid, epoch)))
    const r = lex.validate(T('groupSnapshot'), snap)
    if (!r.success) throw r.error
    return snap
  }

  // GAP side channel (G1): secrets for one epoch, sent pairwise.
  async #sendSecrets(g, to) {
    for (const m of to) {
      await this.c.send(m, { $type: GAP, groupId: g.gid, epoch: g.epoch, creator: g.creator, stateKey: g.stateKey, tagSeed: g.tagSeed })
    }
  }

  // --- pairwise plumbing -----------------------------------------------
  async #connect(peer, force = false) {
    if (this.c.contacts.has(peer)) return true
    // No one-time prekey: several members start sessions with the same peer at
    // once (create, join) and would all claim the same prekey record.
    if (force || this.me < peer) { await this.c.startConversation(peer, null, { useOneTimePreKey: false }); return true }
    if (!this.pending.has(peer)) this.pending.set(peer, new Set())
    return false
  }

  // New sender key = new distributionId (libsignal keys sender keys by it).
  async #rekey(g) {
    g.distId = randomUUID()
    const skdm = await S.SenderKeyDistributionMessage.create(this.c.addr, g.distId, this.c.stores.senderKey)
    const others = g.members.filter((m) => m !== this.me)
    let sent = 0
    for (const m of others) {
      if (await this.#connect(m)) { await this.#sendSkdm(g, m, skdm); sent++ } else this.pending.get(m).add(g.gid)
    }
    this.log(`new sender key for ${g.gid} at epoch ${g.epoch}; SKDM to ${sent}/${others.length} members` +
      (sent < others.length ? ' (rest on their conversationInit)' : ''))
  }

  async #sendSkdm(g, m, skdm) {
    skdm ??= await S.SenderKeyDistributionMessage.create(this.c.addr, g.distId, this.c.stores.senderKey)
    await this.c.send(m, { $type: T('senderKeyDistribution'), groupId: g.gid, distributionMessage: skdm.serialize() })
  }

  async onNewContact(peer) {
    for (const gid of this.pending.get(peer) ?? []) {
      const g = this.groups.get(gid)
      if (g && !g.removed && g.members.includes(peer)) await this.#sendSkdm(g, peer)
    }
    this.pending.delete(peer)
  }

  // --- membership changes ------------------------------------------------
  // Sign without checking admin status (so the demo can also forge).
  signChange(gid, epoch, actions, signerDid = this.me) {
    const ch = { $type: T('groupChange'), groupId: gid, epoch, actions, signerDid }
    return { ...ch, signature: this.c.identity.privateKey.sign(signingInput(ch)) }
  }

  async change(gid, actions) {
    const g = this.groups.get(gid)
    const old = [...g.members]
    const ch = this.signChange(gid, g.epoch + 1, actions)
    const joiners = actions.filter((a) => a.action === 'addMember').map((a) => a.did)
    for (const j of joiners) await this.#connect(j, true) // joiner can't know to start one
    this.stash.set(`${gid}/${ch.epoch}`, this.#newSecrets())
    if (!(await this.#apply(ch))) throw new Error('own change rejected')
    await this.#sendSecrets(g, g.members.filter((m) => m !== this.me)) // joiners: a welcome
    for (const m of old) if (m !== this.me) await this.c.send(m, ch) // incl. removed members
  }

  #signerKey(did) {
    if (did === this.me) return this.c.identity.publicKey
    // Prefer the key pinned by the pairwise session (TOFU / safety number)
    // over the repo record, which the signer's PDS could swap.
    const pinned = this.c.stores.identityStore.getIdentity(this.c.peerAddr(did))
    return pinned
  }

  async #apply(ch) {
    const g = this.groups.get(ch.groupId)
    const reject = (why) => { if (g) g.rejected.push({ ch, why }); this.log(`REJECTED groupChange epoch ${ch.epoch} from ${ch.signerDid}: ${why}`); return false }
    if (!g || g.removed) return reject('unknown group')
    if (ch.epoch !== g.epoch + 1) return reject(`epoch ${ch.epoch} != ${g.epoch}+1`)
    if (!g.admins.includes(ch.signerDid)) return reject('signer is not a current admin')
    const key = (await this.#signerKey(ch.signerDid)) ??
      S.PublicKey.deserialize(this.c.pds.getRecord(ch.signerDid, `${NS}.identity`, 'self').identityKey)
    if (!key.verify(signingInput(ch), ch.signature)) return reject('bad signature')

    const members = new Set(g.members), admins = new Set(g.admins)
    for (const { action, did } of ch.actions) {
      if (action === 'addMember') members.add(did)
      else if (action === 'removeMember') { members.delete(did); admins.delete(did) }
      else if (action === 'addAdmin' && members.has(did)) admins.add(did)
      else if (action === 'removeAdmin') admins.delete(did)
    }
    if (!admins.size) return reject('would leave no admin')
    Object.assign(g, { epoch: ch.epoch, members: [...members], admins: [...admins], prevTagSeed: g.tagSeed })
    const desc = ch.actions.map((a) => `${a.action} ${a.did}`).join(', ')
    if (!members.has(this.me)) { g.removed = true; this.log(`applied epoch ${g.epoch} (${desc}): I was removed`); return true }
    const sec = this.stash.get(`${g.gid}/${g.epoch}`)
    if (sec) { Object.assign(g, sec); this.stash.delete(`${g.gid}/${g.epoch}`) } else this.log(`no secrets yet for epoch ${g.epoch}`)
    this.log(`applied epoch ${g.epoch} (${desc}) signed by ${ch.signerDid}`)
    if (g.creator === this.me) this.#writeSnapshot(g)
    if (rekeys(ch.actions)) await this.#rekey(g)
    return true
  }

  // Incoming pairwise content the base Client does not handle.
  async onContent(from, content) {
    if (content.$type === T('senderKeyDistribution')) {
      const g = this.groups.get(content.groupId)
      if (g && !g.members.includes(from)) return false // known group, not a member: ignore
      const m = S.SenderKeyDistributionMessage.deserialize(content.distributionMessage)
      await S.processSenderKeyDistributionMessage(this.c.peerAddr(from), m, this.c.stores.senderKey)
      return false
    }
    if (content.$type === T('groupChange')) return this.#apply(content)
    if (content.$type === GAP) {
      const { groupId: gid, epoch, creator, stateKey, tagSeed } = content
      const g = this.groups.get(gid)
      if (g) { // remaining member: secrets for the next epoch
        if (epoch === g.epoch) Object.assign(g, { stateKey, tagSeed })
        else this.stash.set(`${gid}/${epoch}`, { stateKey, tagSeed })
        return true
      }
      // Welcome: read the encrypted snapshot from the creator's repo.
      const snap = this.#readSnapshot(creator, gid, epoch, stateKey)
      if (!snap.members.includes(this.me)) return false
      const ng = this.#init(gid, { epoch, members: snap.members, admins: snap.admins, title: snap.title, creator, stateKey, tagSeed })
      this.log(`joined ${gid} "${snap.title}" at epoch ${epoch} via groupState from ${creator} (${snap.members.length} members)`)
      await this.#rekey(ng)
      return true
    }
    return false
  }

  // --- group messages ----------------------------------------------------
  async sendText(gid, text) {
    const g = this.groups.get(gid)
    const ct = await S.groupEncrypt(this.c.addr, g.distId, this.c.stores.senderKey, encodePlaintext({ $type: T('text'), text }))
    const ref = this.c.pds.putRecord(this.me, `${NS}.message`, null, {
      tag: groupTag(g.tagSeed, this.me, windowOf(this.c.clock.now())),
      envelopeType: 'senderKey', ciphertext: ct.serialize(), formatVersion: FORMAT,
    })
    this.c.seen.add(`${ref.did}/${ref.rkey}`)
    return ref
  }

  async decrypt(senderDid, rec) {
    if (rec.envelopeType !== 'senderKey') throw new Error('not a group message')
    return decodePlaintext(await S.groupDecrypt(this.c.peerAddr(senderDid), this.c.stores.senderKey, rec.ciphertext))
  }

  // Fetch any public message record and try to decrypt it (used by checks).
  async tryDecrypt(ref) {
    try { return (await this.decrypt(ref.did, this.c.pds.getRecord(ref.did, ref.collection, ref.rkey))).text }
    catch (e) { return new Error(e.message) }
  }

  async poll() {
    let got = 0
    const w = windowOf(this.c.clock.now())
    for (const g of this.groups.values()) {
      if (g.removed) continue
      for (const m of g.members) {
        if (m === this.me) continue
        for (const seed of [g.tagSeed, g.prevTagSeed]) {
          if (!seed) continue
          for (const win of [w, w - 1]) {
            for (const ref of this.c.indexer.lookup(groupTag(seed, m, win))) {
              const key = `${ref.did}/${ref.rkey}`
              if (ref.did !== m || this.c.seen.has(key)) continue
              const rec = this.c.pds.getRecord(ref.did, ref.collection, ref.rkey)
              if (!rec) continue
              try {
                const { text } = await this.decrypt(m, rec)
                this.c.seen.add(key)
                g.inbox.push({ from: m, text, rkey: ref.rkey })
                this.c.log(`${this.c.name} <- ${m} in ${g.gid}: "${text}"  [senderKey]`)
                got++
              } catch (e) { g.failed.set(key, e.message) } // SKDM may still be in flight; retried next poll
            }
          }
        }
      }
    }
    return got
  }
}
