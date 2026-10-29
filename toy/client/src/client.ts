// AtsigClient: one account, one device (deviceId 1), Signal sessions and sender
// keys over ATProto records. See toy/CONTRACT.md and docs/signal-on-atproto.md.

import { randomBytes, randomInt, randomUUID } from 'node:crypto'
import { TID } from '@atproto/common-web'
import {
  CiphertextMessageType,
  IdentityKeyPair,
  KEMKeyPair,
  KEMPublicKey,
  KyberPreKeyRecord,
  PreKeyBundle,
  PreKeyRecord,
  PreKeySignalMessage,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderKeyDistributionMessage,
  SenderKeyMessage,
  SignalMessage,
  SignedPreKeyRecord,
  groupDecrypt,
  groupEncrypt,
  processPreKeyBundle,
  processSenderKeyDistributionMessage,
  signalDecrypt,
  signalDecryptPreKey,
  signalEncrypt,
} from '@signalapp/libsignal-client'
import {
  FORMAT_VERSION,
  NSID,
  currentWindow,
  decodePlaintext,
  encodePlaintext,
  firstContactTag,
  groupChangeSigningBytes,
  groupStateRkey,
  groupTag,
  lexicons,
  pairTag,
  sealGroupState,
  tagToParam,
  type Content,
  type GroupAction,
  type GroupChange,
  type GroupSnapshot,
} from '../../shared/src/index.ts'
import { SignalStores, StateFile, b64, bytes, unb64, type GroupInfo, type State } from './state.ts'
import { AtprotoTransport, type MessageView, type Transport } from './transport.ts'

export const DEVICE_ID = 1
const PREKEY_BATCH = 10
const PREKEY_LOW_WATER = 3
const TAG_CHUNK = 50
const PAGE_LIMIT = 100
const DEFS = 'is.neuros.atsignal.defs'

export type ClientOptions = {
  /** State directory; the account's state is `<home>/<handle>.json`. */
  home: string
  handle: string
  password: string
  /** Defaults to `${first label of handle}@example.test`. */
  email?: string
  /** Defaults to the real PDS/AppView transport. */
  transport?: Transport
}

export type InboxItem =
  | { type: 'text'; from: string; groupId?: string; text: string; rkey: string }
  | { type: 'error'; from: string; groupId?: string; error: string; rkey: string }
  | {
      type: 'group'
      from: string
      groupId: string
      event: 'joined' | 'snapshot' | 'change' | 'removed'
      epoch: number
      members: string[]
      admins: string[]
      title?: string
      actions?: GroupAction[]
      rkey: string
    }

type TagInfo = { kind: 'firstContact' } | { kind: 'pair'; did: string } | { kind: 'group'; groupId: string }

type ProcessResult = { items: InboxItem[]; defer?: boolean }

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e))

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
/** Random base62 string (rejection sampling, no modulo bias). */
export function randomBase62(len: number): string {
  let out = ''
  while (out.length < len) {
    for (const b of randomBytes(len * 2)) {
      if (b < 248 && out.length < len) out += BASE62[b % 62]
    }
  }
  return out
}

function field<T>(v: Record<string, unknown> | undefined, k: string, check: (x: unknown) => boolean, what: string): T {
  const x = v?.[k]
  if (!check(x)) throw new Error(`${what}: missing or invalid ${k}`)
  return x as T
}
const isBytes = (x: unknown): boolean => x instanceof Uint8Array
const isInt = (x: unknown): boolean => Number.isInteger(x)

export class AtsigClient {
  readonly handle: string
  readonly transport: Transport
  readonly file: StateFile
  readonly stores: SignalStores
  private readonly password: string
  private readonly email: string
  private loggedIn = false

  constructor(opts: ClientOptions) {
    this.handle = opts.handle.replace(/^@/, '')
    this.password = opts.password
    this.email = opts.email ?? `${this.handle.split('.')[0]}@example.test`
    this.transport = opts.transport ?? new AtprotoTransport()
    this.file = new StateFile(opts.home, this.handle)
    this.stores = new SignalStores(() => this.file.state)
  }

  get state(): State {
    return this.file.state
  }

  get did(): string {
    const did = this.state.did
    if (!did) throw new Error('no DID yet; run register first')
    return did
  }

  private get localAddress(): ProtocolAddress {
    return ProtocolAddress.new(this.did, DEVICE_ID)
  }

  private save(): void {
    this.file.save()
  }

  // -------------------------------------------------------------------------
  // Account and keys

  /** Creates the account (or logs in), generates keys if needed, and publishes identity, device and prekey records. */
  async register(): Promise<{ did: string; handle: string; created: boolean }> {
    const { did, created } = await this.transport.createOrLogin(this.handle, this.password, this.email)
    this.loggedIn = true
    if (this.state.did && this.state.did !== did) this.file.reset() // a different account under the same handle
    this.state.did = did
    if (!this.state.identityKeyPair) this.generateKeys()
    this.save()
    await this.publishKeys()
    this.save()
    return { did, handle: this.handle, created }
  }

  private generateKeys(): void {
    const st = this.state
    const identity = IdentityKeyPair.generate()
    st.identityKeyPair = b64(identity.serialize())
    st.registrationId = randomInt(1, 16380)

    const spkPriv = PrivateKey.generate()
    const spkPub = spkPriv.getPublicKey()
    const spk = SignedPreKeyRecord.new(1, Date.now(), spkPub, spkPriv, identity.privateKey.sign(spkPub.serialize()))
    st.signedPreKeys['1'] = b64(spk.serialize())
    st.signedPreKeyId = 1

    const kem = KEMKeyPair.generate()
    const kpk = KyberPreKeyRecord.new(1, Date.now(), kem, identity.privateKey.sign(kem.getPublicKey().serialize()))
    st.kyberPreKeys['1'] = b64(kpk.serialize())
    st.kyberPreKeyId = 1

    st.deviceRkey = randomBase62(16)
    this.generatePreKeys(PREKEY_BATCH)
  }

  private generatePreKeys(n: number): string[] {
    const ids: string[] = []
    for (let i = 0; i < n; i++) {
      const id = this.state.nextPreKeyId++
      const priv = PrivateKey.generate()
      const rec = PreKeyRecord.new(id, priv.getPublicKey(), priv)
      this.state.preKeys[String(id)] = { record: b64(rec.serialize()), rkey: TID.nextStr() }
      ids.push(String(id))
    }
    return ids
  }

  private async writeRecord(collection: string, rkey: string, record: Record<string, unknown>, create = false): Promise<void> {
    const full = { $type: collection, ...record }
    lexicons.assertValidRecord(collection, full)
    if (create) await this.transport.createRecord(collection, rkey, full)
    else await this.transport.putRecord(collection, rkey, full)
  }

  private async publishPreKey(id: string): Promise<void> {
    const e = this.state.preKeys[id]!
    const rec = PreKeyRecord.deserialize(unb64(e.record))
    await this.writeRecord(NSID.preKey, e.rkey, {
      deviceId: DEVICE_ID,
      preKeyId: rec.id(),
      publicKey: rec.publicKey().serialize(),
      formatVersion: FORMAT_VERSION,
    })
  }

  /** Writes identity/device/preKey records; removes stale device and preKey records from earlier runs. */
  private async publishKeys(): Promise<void> {
    const st = this.state
    const now = new Date().toISOString()
    const identity = this.stores.identityKeyPair()
    await this.writeRecord(NSID.identity, 'self', {
      identityKey: identity.publicKey.serialize(),
      formatVersion: FORMAT_VERSION,
      createdAt: now,
    })

    const spk = SignedPreKeyRecord.deserialize(unb64(st.signedPreKeys[String(st.signedPreKeyId)]!))
    const kpk = KyberPreKeyRecord.deserialize(unb64(st.kyberPreKeys[String(st.kyberPreKeyId)]!))
    await this.writeRecord(NSID.device, st.deviceRkey!, {
      deviceId: DEVICE_ID,
      registrationId: st.registrationId,
      signedPreKey: { keyId: spk.id(), publicKey: spk.publicKey().serialize(), signature: spk.signature() },
      kyberPreKey: { keyId: kpk.id(), publicKey: kpk.publicKey().serialize(), signature: kpk.signature() },
      formatVersion: FORMAT_VERSION,
      createdAt: now,
    })
    for (const r of await this.transport.listRecords(this.did, NSID.device)) {
      if (r.rkey !== st.deviceRkey) await this.transport.deleteRecord(NSID.device, r.rkey)
    }

    const ours = new Map(Object.entries(st.preKeys).map(([id, e]) => [e.rkey, id]))
    const published = new Set<string>()
    for (const r of await this.transport.listRecords(this.did, NSID.preKey)) {
      if (ours.has(r.rkey)) published.add(r.rkey)
      else await this.transport.deleteRecord(NSID.preKey, r.rkey)
    }
    for (const [rkey, id] of ours) if (!published.has(rkey)) await this.publishPreKey(id)
  }

  /** Deletes public records of consumed one-time prekeys and tops the pool up. */
  private async afterPreKeyUse(): Promise<void> {
    this.stores.purgeUsedPreKeys()
    const rkeys = this.stores.consumedPreKeyRkeys.splice(0)
    for (const rkey of rkeys) {
      try {
        await this.transport.deleteRecord(NSID.preKey, rkey)
      } catch {
        // Already gone, or the PDS is unreachable; register() also prunes stale records.
      }
    }
    if (Object.keys(this.state.preKeys).length < PREKEY_LOW_WATER) {
      const ids = this.generatePreKeys(PREKEY_BATCH)
      this.save()
      try {
        for (const id of ids) await this.publishPreKey(id)
      } catch {
        // register() republishes missing prekey records.
      }
    }
  }

  private async ready(): Promise<void> {
    if (!this.state.identityKeyPair || !this.state.did) throw new Error(`no keys for ${this.handle}; run register first`)
    if (this.loggedIn) return
    const { did } = await this.transport.login(this.handle, this.password)
    if (did !== this.state.did) throw new Error(`account DID changed (${this.state.did} -> ${did}); run register again`)
    this.loggedIn = true
  }

  whoami(): { handle: string; did?: string; identityKey?: string; contacts: string[]; groups: GroupInfo[] } {
    return {
      handle: this.handle,
      did: this.state.did,
      identityKey: this.state.identityKeyPair ? b64(this.stores.identityKeyPair().publicKey.serialize()) : undefined,
      contacts: Object.keys(this.state.contacts),
      groups: Object.values(this.state.groups),
    }
  }

  groups(): GroupInfo[] {
    return Object.values(this.state.groups).filter((g) => !g.left)
  }

  // -------------------------------------------------------------------------
  // Pairwise

  private async writeMessage(tag: Uint8Array, envelopeType: string, ciphertext: Uint8Array): Promise<string> {
    const rkey = TID.nextStr()
    await this.writeRecord(NSID.message, rkey, { tag, envelopeType, ciphertext, formatVersion: FORMAT_VERSION }, true)
    return rkey
  }

  /** Fetches the peer's identity, device and one prekey, and starts a session (X3DH/PQXDH). */
  private async establishSession(theirDid: string): Promise<void> {
    const [idRec, devices, preKeys] = await Promise.all([
      this.transport.getRecord(theirDid, NSID.identity, 'self'),
      this.transport.listRecords(theirDid, NSID.device),
      this.transport.listRecords(theirDid, NSID.preKey),
    ])
    if (!idRec) throw new Error(`${theirDid} has no ${NSID.identity} record`)
    const identityKey = PublicKey.deserialize(bytes(field<Uint8Array>(idRec, 'identityKey', isBytes, 'identity')))
    const device = devices
      .filter((d) => d.value.deviceId === DEVICE_ID)
      .sort((a, b) => String(b.value.createdAt).localeCompare(String(a.value.createdAt)))[0]
    if (!device) throw new Error(`${theirDid} has no device ${DEVICE_ID}`)
    const dv = device.value
    const spk = field<Record<string, unknown>>(dv, 'signedPreKey', (x) => !!x && typeof x === 'object', 'device')
    const kpk = field<Record<string, unknown>>(dv, 'kyberPreKey', (x) => !!x && typeof x === 'object', 'device')
    const candidates = preKeys.filter((p) => p.value.deviceId === DEVICE_ID)
    const pk = candidates.length ? candidates[randomInt(candidates.length)]!.value : undefined

    const bundle = PreKeyBundle.new(
      field<number>(dv, 'registrationId', isInt, 'device'),
      DEVICE_ID,
      pk ? field<number>(pk, 'preKeyId', isInt, 'preKey') : null,
      pk ? PublicKey.deserialize(bytes(field<Uint8Array>(pk, 'publicKey', isBytes, 'preKey'))) : null,
      field<number>(spk, 'keyId', isInt, 'signedPreKey'),
      PublicKey.deserialize(bytes(field<Uint8Array>(spk, 'publicKey', isBytes, 'signedPreKey'))),
      bytes(field<Uint8Array>(spk, 'signature', isBytes, 'signedPreKey')),
      identityKey,
      field<number>(kpk, 'keyId', isInt, 'kyberPreKey'),
      KEMPublicKey.deserialize(bytes(field<Uint8Array>(kpk, 'publicKey', isBytes, 'kyberPreKey'))),
      bytes(field<Uint8Array>(kpk, 'signature', isBytes, 'kyberPreKey')),
    )
    await processPreKeyBundle(bundle, ProtocolAddress.new(theirDid, DEVICE_ID), this.localAddress, this.stores.session, this.stores.identity)
  }

  private async encryptTo(theirDid: string, content: Content): Promise<{ type: number; body: Uint8Array }> {
    const msg = await signalEncrypt(
      bytes(encodePlaintext(content)),
      ProtocolAddress.new(theirDid, DEVICE_ID),
      this.localAddress,
      this.stores.session,
      this.stores.identity,
    )
    return { type: msg.type(), body: msg.serialize() }
  }

  /** The seed used for sending: the smallest known one, so both sides converge after simultaneous inits. */
  private sendSeed(theirDid: string): Uint8Array | undefined {
    const seeds = this.state.contacts[theirDid]?.tagSeeds ?? []
    const s = [...seeds].sort()[0]
    return s ? unb64(s) : undefined
  }

  /** Makes sure we have a session and a shared tag seed with `theirDid`. */
  private async ensureConversation(theirDid: string): Promise<void> {
    const session = await this.stores.session.getSession(ProtocolAddress.new(theirDid, DEVICE_ID))
    if (!session?.hasCurrentState()) await this.establishSession(theirDid)
    if (!this.sendSeed(theirDid)) {
      const seed = new Uint8Array(randomBytes(32))
      const { body } = await this.encryptTo(theirDid, { $type: `${DEFS}#conversationInit`, tagSeed: seed })
      this.state.contacts[theirDid] = { tagSeeds: [b64(seed)] }
      this.save()
      await this.writeMessage(firstContactTag(theirDid), 'firstContact', body)
    }
    this.save()
  }

  /** Sends any content pairwise, establishing the conversation on demand. */
  private async sendPairwise(theirDid: string, content: Content): Promise<string> {
    if (theirDid === this.did) throw new Error('cannot send to yourself')
    await this.ensureConversation(theirDid)
    const { type, body } = await this.encryptTo(theirDid, content)
    this.save()
    const envelopeType = type === CiphertextMessageType.PreKey ? 'prekey' : 'whisper'
    return this.writeMessage(pairTag(this.sendSeed(theirDid)!, this.did, theirDid, currentWindow()), envelopeType, body)
  }

  /** Sends a text to a handle or DID. */
  async send(toHandleOrDid: string, text: string): Promise<{ to: string; rkey: string }> {
    await this.ready()
    const to = await this.transport.resolveDid(toHandleOrDid)
    const rkey = await this.sendPairwise(to, { $type: `${DEFS}#text`, text })
    return { to, rkey }
  }

  // -------------------------------------------------------------------------
  // Groups

  private group(groupId: string): GroupInfo {
    const g = this.state.groups[groupId]
    if (!g || g.left) throw new Error(`not a member of group ${groupId}`)
    return g
  }

  private snapshot(g: GroupInfo): GroupSnapshot {
    return {
      $type: `${DEFS}#groupSnapshot`,
      groupId: g.groupId,
      epoch: g.epoch,
      members: [...g.members],
      admins: [...g.admins],
      ...(g.title !== undefined ? { title: g.title } : {}),
    }
  }

  private async writeGroupState(g: GroupInfo): Promise<void> {
    // Never the groupId itself: it keys the group tag and the state encryption.
    await this.writeRecord(NSID.groupState, groupStateRkey(g.groupId), {
      epoch: g.epoch,
      stateCiphertext: sealGroupState(g.groupId, this.snapshot(g)),
      formatVersion: FORMAT_VERSION,
    })
  }

  /** Starts a new sender-key chain for us in `g` and sends its SKDM pairwise to `to`. */
  private async rotateSenderKey(g: GroupInfo, to: string[]): Promise<void> {
    g.myDistributionId = randomUUID()
    const skdm = await SenderKeyDistributionMessage.create(this.localAddress, g.myDistributionId, this.stores.senderKey)
    this.save()
    for (const did of to) {
      if (did === this.did) continue
      await this.sendPairwise(did, { $type: `${DEFS}#senderKeyDistribution`, groupId: g.groupId, distributionMessage: skdm.serialize() })
    }
  }

  /** Creates a group with us as the only admin. Members may be DIDs or handles. */
  async groupCreate(title: string, members: string[]): Promise<string> {
    await this.ready()
    const dids = [this.did]
    for (const m of members) {
      const did = await this.transport.resolveDid(m)
      if (!dids.includes(did)) dids.push(did)
    }
    const g: GroupInfo = { groupId: randomBase62(22), title, epoch: 0, members: dids, admins: [this.did], myDistributionId: randomUUID() }
    this.state.groups[g.groupId] = g
    this.save()
    await this.writeGroupState(g)
    for (const did of dids) if (did !== this.did) await this.sendPairwise(did, this.snapshot(g))
    await this.rotateSenderKey(g, dids)
    return g.groupId
  }

  async groupSend(groupId: string, text: string): Promise<{ rkey: string }> {
    await this.ready()
    const g = this.group(groupId)
    const msg = await groupEncrypt(this.localAddress, g.myDistributionId, this.stores.senderKey, bytes(encodePlaintext({ $type: `${DEFS}#text`, text })))
    this.save()
    const rkey = await this.writeMessage(groupTag(groupId, currentWindow()), 'senderKey', msg.serialize())
    return { rkey }
  }

  /** Applies actions to `g` in place. Returns DIDs added and removed as members. */
  private applyActions(g: GroupInfo, actions: GroupAction[]): { added: string[]; removed: string[] } {
    const added: string[] = []
    const removed: string[] = []
    for (const { action, did } of actions) {
      if (action === 'addMember' && !g.members.includes(did)) {
        g.members.push(did)
        added.push(did)
      } else if (action === 'removeMember' && g.members.includes(did)) {
        g.members = g.members.filter((m) => m !== did)
        if (g.admins.length > 1 || g.admins[0] !== did) g.admins = g.admins.filter((a) => a !== did)
        removed.push(did)
      } else if (action === 'addAdmin' && g.members.includes(did) && !g.admins.includes(did)) {
        g.admins.push(did)
      } else if (action === 'removeAdmin' && g.admins.length > 1) {
        g.admins = g.admins.filter((a) => a !== did)
      }
    }
    for (const did of removed) {
      const dists = this.state.senderKeyDists[g.groupId]
      if (dists?.[did]) {
        this.stores.forgetSenderKeys(did, dists[did]!)
        delete dists[did]
      }
    }
    return { added, removed }
  }

  private signChange(g: GroupInfo, actions: GroupAction[]): GroupChange {
    const unsigned = { $type: `${DEFS}#groupChange` as const, groupId: g.groupId, epoch: g.epoch + 1, actions, signerDid: this.did }
    const signature = this.stores.identityKeyPair().privateKey.sign(bytes(groupChangeSigningBytes(unsigned)))
    return { ...unsigned, signature }
  }

  private async adminChange(groupId: string, action: 'addMember' | 'removeMember', target: string): Promise<{ epoch: number; members: string[] }> {
    await this.ready()
    const g = this.group(groupId)
    if (!g.admins.includes(this.did)) throw new Error(`not an admin of ${groupId}`)
    const did = await this.transport.resolveDid(target)
    if (action === 'removeMember' && !g.members.includes(did)) throw new Error(`${did} is not a member`)
    if (action === 'addMember' && g.members.includes(did)) throw new Error(`${did} is already a member`)
    if (did === this.did) throw new Error('cannot add or remove yourself')

    const change = this.signChange(g, [{ action, did }])
    const before = [...g.members]
    // Change goes to every current member, including the one being removed.
    for (const m of before) if (m !== this.did) await this.sendPairwise(m, change)
    this.applyActions(g, change.actions)
    g.epoch = change.epoch
    this.save()
    await this.writeGroupState(g)
    if (action === 'addMember') await this.sendPairwise(did, this.snapshot(g))
    await this.rotateSenderKey(g, g.members)
    return { epoch: g.epoch, members: [...g.members] }
  }

  groupAdd(groupId: string, did: string) {
    return this.adminChange(groupId, 'addMember', did)
  }

  groupRemove(groupId: string, did: string) {
    return this.adminChange(groupId, 'removeMember', did)
  }

  /** The signer's identity key from their identity record; must match the key our sessions trust. */
  private async signerIdentity(did: string): Promise<PublicKey> {
    const rec = await this.transport.getRecord(did, NSID.identity, 'self')
    if (!rec) throw new Error(`${did} has no identity record`)
    const fetched = PublicKey.deserialize(bytes(field<Uint8Array>(rec, 'identityKey', isBytes, 'identity')))
    const stored = await this.stores.identity.getIdentity(ProtocolAddress.new(did, DEVICE_ID))
    if (stored && !stored.equals(fetched)) throw new Error(`identity key of ${did} changed`)
    return fetched
  }

  private groupEvent(from: string, rkey: string, g: GroupInfo, event: 'joined' | 'snapshot' | 'change' | 'removed', actions?: GroupAction[]): InboxItem {
    return { type: 'group', from, groupId: g.groupId, event, epoch: g.epoch, members: [...g.members], admins: [...g.admins], title: g.title, actions, rkey }
  }

  private async onGroupChange(from: string, rkey: string, ch: GroupChange): Promise<InboxItem[]> {
    const g = this.state.groups[ch.groupId]
    if (!g || g.left) return [] // not (yet) a member; a snapshot brings us in
    if (ch.epoch <= g.epoch) return [] // already applied (e.g. we joined from a newer snapshot)
    const fail = (error: string): InboxItem[] => [{ type: 'error', from, groupId: g.groupId, error, rkey }]
    if (ch.epoch !== g.epoch + 1) return fail(`groupChange epoch ${ch.epoch} skips ahead of ${g.epoch}`)
    if (!g.admins.includes(ch.signerDid)) return fail(`groupChange signer ${ch.signerDid} is not an admin`)
    let key: PublicKey
    try {
      key = await this.signerIdentity(ch.signerDid)
    } catch (e) {
      return fail(`groupChange signer: ${errMsg(e)}`)
    }
    if (!key.verify(bytes(groupChangeSigningBytes(ch)), bytes(ch.signature))) return fail('groupChange signature invalid')

    const { added, removed } = this.applyActions(g, ch.actions)
    g.epoch = ch.epoch
    if (!g.members.includes(this.did)) {
      g.left = true
      delete this.state.senderKeyDists[g.groupId]
      this.save()
      return [this.groupEvent(from, rkey, g, 'removed', ch.actions)]
    }
    this.save()
    // Policy (decision 4): on any join or removal every remaining member rotates.
    if (added.length || removed.length) await this.rotateSenderKey(g, g.members)
    return [this.groupEvent(from, rkey, g, 'change', ch.actions)]
  }

  private async onGroupSnapshot(from: string, rkey: string, snap: GroupSnapshot): Promise<InboxItem[]> {
    if (!snap.members.includes(this.did)) return []
    const fail = (error: string): InboxItem[] => [{ type: 'error', from, groupId: snap.groupId, error, rkey }]
    if (!snap.admins.includes(from)) return fail('groupSnapshot sender is not an admin in it')
    const g = this.state.groups[snap.groupId]
    if (g && !g.left) {
      if (!g.admins.includes(from)) return fail('groupSnapshot sender is not an admin')
      if (snap.epoch < g.epoch) return []
      Object.assign(g, { epoch: snap.epoch, members: [...snap.members], admins: [...snap.admins], title: snap.title ?? g.title })
      this.save()
      return [this.groupEvent(from, rkey, g, 'snapshot')]
    }
    const joined: GroupInfo = {
      groupId: snap.groupId,
      title: snap.title,
      epoch: snap.epoch,
      members: [...snap.members],
      admins: [...snap.admins],
      myDistributionId: randomUUID(),
    }
    this.state.groups[snap.groupId] = joined
    this.save()
    await this.rotateSenderKey(joined, joined.members)
    return [this.groupEvent(from, rkey, joined, 'joined')]
  }

  private async onSenderKeyDistribution(from: string, groupId: string, distributionMessage: Uint8Array): Promise<void> {
    const g = this.state.groups[groupId]
    if (g && !g.left && !g.members.includes(from)) return // not a member: ignore
    const skdm = SenderKeyDistributionMessage.deserialize(bytes(distributionMessage))
    await processSenderKeyDistributionMessage(ProtocolAddress.new(from, DEVICE_ID), skdm, this.stores.senderKey)
    const byGroup = (this.state.senderKeyDists[groupId] ??= {})
    const list = (byGroup[from] ??= [])
    if (!list.includes(skdm.distributionId())) list.push(skdm.distributionId())
  }

  // -------------------------------------------------------------------------
  // Inbox

  private inboxTags(): Map<string, { tag: Uint8Array; info: TagInfo }> {
    const me = this.did
    const w = currentWindow()
    // current-1 and current per CONTRACT.md, plus current+1 to tolerate clock skew.
    const windows = [w - 1, w, w + 1]
    const out = new Map<string, { tag: Uint8Array; info: TagInfo }>()
    const add = (tag: Uint8Array, info: TagInfo) => out.set(tagToParam(tag), { tag, info })
    add(firstContactTag(me), { kind: 'firstContact' })
    for (const [did, c] of Object.entries(this.state.contacts)) {
      for (const s of c.tagSeeds) for (const win of windows) add(pairTag(unb64(s), did, me, win), { kind: 'pair', did })
    }
    for (const g of this.groups()) for (const win of windows) add(groupTag(g.groupId, win), { kind: 'group', groupId: g.groupId })
    return out
  }

  /** Queries the AppView for `tags` from `cursor`, all pages. Returns messages (oldest first) and a safe new cursor. */
  private async fetchMessages(tags: Uint8Array[], cursor: string | undefined): Promise<{ messages: MessageView[]; cursor?: string }> {
    const messages: MessageView[] = []
    const finals: Array<string | undefined> = []
    for (let i = 0; i < tags.length; i += TAG_CHUNK) {
      const chunk = tags.slice(i, i + TAG_CHUNK)
      let c = cursor
      for (;;) {
        const res = await this.transport.getMessagesByTag(chunk, c, PAGE_LIMIT)
        messages.push(...res.messages)
        if (res.cursor) c = res.cursor
        if (res.messages.length < PAGE_LIMIT || !res.cursor) break
      }
      finals.push(c)
    }
    // With several chunks, keep the smallest cursor so no chunk misses messages
    // indexed between our queries; already-seen messages are skipped anyway.
    let next: string | undefined
    if (finals.length === 1) next = finals[0]
    else if (finals.every((f) => f !== undefined)) next = finals.reduce((a, b) => (Number(a) <= Number(b) ? a : b))
    else next = cursor
    if (finals.length > 1) messages.sort((a, b) => a.indexedAt.localeCompare(b.indexedAt))
    return { messages, cursor: next }
  }

  /** Fetches, decrypts and applies new messages. Never throws on a bad message. */
  async inbox(): Promise<InboxItem[]> {
    await this.ready()
    this.stores.purgeUsedPreKeys()
    const out: InboxItem[] = []
    const deferred: Array<{ m: MessageView; historical: boolean }> = []
    const queried = new Set<string>()

    const run = async (tags: Map<string, { tag: Uint8Array }>, cursor: string | undefined, historical: boolean) => {
      for (const k of tags.keys()) queried.add(k)
      const res = await this.fetchMessages([...tags.values()].map((t) => t.tag), cursor)
      for (const m of res.messages) {
        const r = await this.processMessage(m, false)
        if (r.defer) deferred.push({ m, historical })
        out.push(...r.items)
      }
      return res.cursor
    }

    const newCursor = await run(this.inboxTags(), this.state.cursor, false)
    // New contacts or groups learned above have tags we haven't queried yet:
    // fetch those from the beginning (they are fresh, so history is short).
    for (let round = 0; round < 10; round++) {
      const fresh = new Map([...this.inboxTags()].filter(([k]) => !queried.has(k)))
      if (fresh.size === 0) break
      await run(fresh, undefined, true)
    }
    // Sender-key messages that arrived before their SKDM in this batch get one retry.
    for (const { m, historical } of deferred) {
      const r = await this.processMessage(m, true)
      // A failure on group history fetched for a group we just joined is expected
      // (it predates our sender keys), so it is dropped rather than reported.
      if (!(historical && r.items.every((i) => i.type === 'error'))) out.push(...r.items)
    }
    if (newCursor !== undefined) this.state.cursor = newCursor
    this.save()
    return out
  }

  private async processMessage(m: MessageView, lastTry: boolean): Promise<ProcessResult> {
    const key = `${m.did}/${m.rkey}`
    if (m.did === this.did || this.file.seen.has(key)) return { items: [] }
    const info = this.inboxTags().get(tagToParam(m.tag))?.info
    const markSeen = () => {
      this.file.seen.add(key)
      this.save()
    }
    if (!info || (info.kind === 'pair' && info.did !== m.did)) {
      markSeen()
      return { items: [] }
    }
    const groupId = info.kind === 'group' ? info.groupId : undefined
    const errorItem = (error: string): InboxItem => ({ type: 'error', from: m.did, ...(groupId ? { groupId } : {}), error, rkey: m.rkey })

    let content: Content
    try {
      if (m.envelopeType === 'senderKey') {
        if (info.kind !== 'group') throw new Error('senderKey message under a non-group tag')
        const g = this.state.groups[info.groupId]
        if (!g || g.left) throw new Error('not a member of this group')
        if (!g.members.includes(m.did)) throw new Error('sender is not a group member')
        const dist = SenderKeyMessage.deserialize(bytes(m.ciphertext)).distributionId()
        if (!this.state.senderKeyDists[g.groupId]?.[m.did]?.includes(dist)) {
          if (!lastTry) return { items: [], defer: true }
          throw new Error(`no sender key for distribution ${dist}`)
        }
        content = decodePlaintext(await groupDecrypt(ProtocolAddress.new(m.did, DEVICE_ID), this.stores.senderKey, bytes(m.ciphertext)))
      } else {
        if (info.kind === 'group') throw new Error(`${m.envelopeType} message under a group tag`)
        content = decodePlaintext(await this.decryptPairwise(m))
      }
    } catch (e) {
      if (m.envelopeType === 'senderKey' && !lastTry) return { items: [], defer: true }
      markSeen()
      return { items: [errorItem(errMsg(e))] }
    } finally {
      this.save()
    }

    let items: InboxItem[] = []
    try {
      items = await this.handleContent(m, content, groupId)
    } catch (e) {
      items = [errorItem(`handling ${content.$type}: ${errMsg(e)}`)]
    }
    markSeen()
    return { items }
  }

  private async decryptPairwise(m: MessageView): Promise<Uint8Array> {
    const addr = ProtocolAddress.new(m.did, DEVICE_ID)
    const s = this.stores
    const ct = bytes(m.ciphertext)
    let prekey = m.envelopeType === 'prekey' || m.envelopeType === 'firstContact'
    if (m.envelopeType === 'firstContact') {
      try {
        PreKeySignalMessage.deserialize(ct)
      } catch {
        prekey = false // conversationInit over an already established session
      }
    } else if (m.envelopeType !== 'prekey' && m.envelopeType !== 'whisper') {
      throw new Error(`unknown envelopeType ${m.envelopeType}`)
    }
    if (!prekey) return signalDecrypt(SignalMessage.deserialize(ct), addr, this.localAddress, s.session, s.identity)
    const pt = await signalDecryptPreKey(
      PreKeySignalMessage.deserialize(ct),
      addr,
      this.localAddress,
      s.session,
      s.identity,
      s.preKey,
      s.signedPreKey,
      s.kyberPreKey,
    )
    this.save()
    await this.afterPreKeyUse()
    return pt
  }

  private async handleContent(m: MessageView, content: Content, groupId: string | undefined): Promise<InboxItem[]> {
    const from = m.did
    if (content.$type === `${DEFS}#text`) {
      return [{ type: 'text', from, ...(groupId ? { groupId } : {}), text: content.text, rkey: m.rkey }]
    }
    if (groupId) throw new Error('control content over a sender-key message')
    switch (content.$type) {
      case `${DEFS}#conversationInit`: {
        const c = (this.state.contacts[from] ??= { tagSeeds: [] })
        const s = b64(content.tagSeed)
        if (!c.tagSeeds.includes(s)) c.tagSeeds.push(s)
        this.save()
        return []
      }
      case `${DEFS}#senderKeyDistribution`:
        await this.onSenderKeyDistribution(from, content.groupId, content.distributionMessage)
        this.save()
        return []
      case `${DEFS}#groupChange`:
        return this.onGroupChange(from, m.rkey, content)
      case `${DEFS}#groupSnapshot`:
        return this.onGroupSnapshot(from, m.rkey, content)
    }
    return []
  }
}
