// Persistent per-account state and the libsignal store implementations over it.
//
// Everything lives in one JSON file per account (`<home>/<handle>.json`). Byte
// values are stored base64. libsignal records are stored in their own
// serialization (unversioned protobuf; see docs/signal-on-atproto.md §6 q9).

import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  Direction,
  IdentityChange,
  IdentityKeyPair,
  IdentityKeyStore,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyRecord,
  PreKeyStore,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderKeyRecord,
  SenderKeyStore,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
  type Uuid,
} from '@signalapp/libsignal-client'

/** libsignal wants `Uint8Array<ArrayBuffer>`; this copies any byte view into one. */
export function bytes(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b)
}
export const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
export const unb64 = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, 'base64'))

export type GroupInfo = {
  groupId: string
  title?: string
  epoch: number
  members: string[]
  admins: string[]
  /** Our own current sender-key distribution id (uuid) for this group. */
  myDistributionId: string
  /** Set when we were removed from the group. */
  left?: boolean
}

export type Contact = {
  /** All tag seeds seen for this contact (base64). Sends use the smallest, so simultaneous inits converge. */
  tagSeeds: string[]
}

export type State = {
  version: 1
  handle: string
  did?: string
  registrationId?: number
  /** IdentityKeyPair.serialize(), base64. */
  identityKeyPair?: string
  deviceRkey?: string
  /** One-time prekeys by id: serialized record + rkey of the public preKey record. */
  preKeys: Record<string, { record: string; rkey: string }>
  /**
   * Consumed one-time prekeys, kept for PREKEY_GRACE_MS: their public records are
   * deleted at once, but another sender may already have fetched the same record
   * (docs/signal-on-atproto.md open question 11).
   */
  usedPreKeys: Record<string, { record: string; usedAt: number }>
  nextPreKeyId: number
  signedPreKeys: Record<string, string>
  signedPreKeyId?: number
  kyberPreKeys: Record<string, string>
  kyberPreKeyId?: number
  /** `${kyberId}:${signedId}:${b64(baseKey)}` already seen with the last-resort Kyber key. */
  kyberUsed: string[]
  /** Session records by `${did}.${deviceId}`. */
  sessions: Record<string, string>
  /** Remote identity keys by DID (one device per account). */
  identities: Record<string, string>
  /** Sender key records by `${did}.${deviceId}|${distributionId}`. */
  senderKeys: Record<string, string>
  /** Accepted sender-key distribution ids, by group, then sender DID. */
  senderKeyDists: Record<string, Record<string, string[]>>
  contacts: Record<string, Contact>
  groups: Record<string, GroupInfo>
  /** `${did}/${rkey}` of processed messages. */
  seen: string[]
  /** AppView cursor. */
  cursor?: string
}

export function emptyState(handle: string): State {
  return {
    version: 1,
    handle,
    preKeys: {},
    usedPreKeys: {},
    nextPreKeyId: 1,
    signedPreKeys: {},
    kyberPreKeys: {},
    kyberUsed: [],
    sessions: {},
    identities: {},
    senderKeys: {},
    senderKeyDists: {},
    contacts: {},
    groups: {},
    seen: [],
  }
}

/** The JSON state file of one account. */
export class StateFile {
  readonly path: string
  state: State
  seen: Set<string>

  constructor(home: string, handle: string) {
    mkdirSync(home, { recursive: true })
    this.path = join(home, `${handle.replace(/[^A-Za-z0-9._-]/g, '_')}.json`)
    this.state = existsSync(this.path)
      ? { ...emptyState(handle), ...(JSON.parse(readFileSync(this.path, 'utf8')) as State) }
      : emptyState(handle)
    this.seen = new Set(this.state.seen)
  }

  reset(): void {
    this.state = emptyState(this.state.handle)
    this.seen = new Set()
  }

  save(): void {
    this.state.seen = [...this.seen]
    const tmp = `${this.path}.tmp`
    writeFileSync(tmp, JSON.stringify(this.state, null, 1), { mode: 0o600 })
    renameSync(tmp, this.path)
  }
}

/** How long a consumed one-time prekey stays usable for racing senders. */
export const PREKEY_GRACE_MS = 3_600_000

const addrKey = (a: ProtocolAddress): string => `${a.name()}.${a.deviceId()}`

/** All libsignal stores, backed by one State object. */
export class SignalStores {
  readonly session: SessionStore
  readonly identity: IdentityKeyStore
  readonly preKey: PreKeyStore
  readonly signedPreKey: SignedPreKeyStore
  readonly kyberPreKey: KyberPreKeyStore
  readonly senderKey: SenderKeyStore
  /** rkeys of one-time prekeys consumed since the last drain; their public records should be deleted. */
  consumedPreKeyRkeys: string[] = []

  constructor(private readonly get: () => State) {
    const st = get
    const stores = this

    this.session = new (class extends SessionStore {
      async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
        st().sessions[addrKey(name)] = b64(record.serialize())
      }
      async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
        const s = st().sessions[addrKey(name)]
        return s ? SessionRecord.deserialize(unb64(s)) : null
      }
      async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
        return addresses.map((a) => {
          const s = st().sessions[addrKey(a)]
          if (!s) throw new Error(`no session for ${addrKey(a)}`)
          return SessionRecord.deserialize(unb64(s))
        })
      }
    })()

    this.identity = new (class extends IdentityKeyStore {
      async getIdentityKey(): Promise<PrivateKey> {
        return stores.identityKeyPair().privateKey
      }
      async getLocalRegistrationId(): Promise<number> {
        const id = st().registrationId
        if (id === undefined) throw new Error('no registration id; run register first')
        return id
      }
      async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
        const prev = st().identities[name.name()]
        const next = b64(key.serialize())
        st().identities[name.name()] = next
        return prev !== undefined && prev !== next ? IdentityChange.ReplacedExisting : IdentityChange.NewOrUnchanged
      }
      // Trust on first use; a changed key is refused (the toy has no safety-number UI).
      async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, _direction: Direction): Promise<boolean> {
        const prev = st().identities[name.name()]
        return prev === undefined || prev === b64(key.serialize())
      }
      async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
        const prev = st().identities[name.name()]
        return prev ? PublicKey.deserialize(unb64(prev)) : null
      }
    })()

    this.preKey = new (class extends PreKeyStore {
      async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
        const prev = st().preKeys[String(id)]
        st().preKeys[String(id)] = { record: b64(record.serialize()), rkey: prev?.rkey ?? '' }
      }
      async getPreKey(id: number): Promise<PreKeyRecord> {
        const e = st().preKeys[String(id)] ?? st().usedPreKeys[String(id)]
        if (!e) throw new Error(`no prekey ${id}`)
        return PreKeyRecord.deserialize(unb64(e.record))
      }
      async removePreKey(id: number): Promise<void> {
        const e = st().preKeys[String(id)]
        if (!e) return
        if (e.rkey) stores.consumedPreKeyRkeys.push(e.rkey)
        st().usedPreKeys[String(id)] = { record: e.record, usedAt: Date.now() }
        delete st().preKeys[String(id)]
      }
    })()

    this.signedPreKey = new (class extends SignedPreKeyStore {
      async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
        st().signedPreKeys[String(id)] = b64(record.serialize())
      }
      async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
        const s = st().signedPreKeys[String(id)]
        if (!s) throw new Error(`no signed prekey ${id}`)
        return SignedPreKeyRecord.deserialize(unb64(s))
      }
    })()

    this.kyberPreKey = new (class extends KyberPreKeyStore {
      async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
        st().kyberPreKeys[String(id)] = b64(record.serialize())
      }
      async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
        const s = st().kyberPreKeys[String(id)]
        if (!s) throw new Error(`no kyber prekey ${id}`)
        return KyberPreKeyRecord.deserialize(unb64(s))
      }
      // Our only Kyber key is a last-resort key, so it is never deleted. We refuse a
      // second use with the same base key (replay of a PreKeySignalMessage).
      async markKyberPreKeyUsed(kyberPreKeyId: number, signedPreKeyId: number, baseKey: PublicKey): Promise<void> {
        const k = `${kyberPreKeyId}:${signedPreKeyId}:${b64(baseKey.serialize())}`
        if (st().kyberUsed.includes(k)) throw new Error('kyber prekey reused with the same base key')
        st().kyberUsed.push(k)
      }
    })()

    this.senderKey = new (class extends SenderKeyStore {
      async saveSenderKey(sender: ProtocolAddress, distributionId: Uuid, record: SenderKeyRecord): Promise<void> {
        st().senderKeys[`${addrKey(sender)}|${distributionId}`] = b64(record.serialize())
      }
      async getSenderKey(sender: ProtocolAddress, distributionId: Uuid): Promise<SenderKeyRecord | null> {
        const s = st().senderKeys[`${addrKey(sender)}|${distributionId}`]
        return s ? SenderKeyRecord.deserialize(unb64(s)) : null
      }
    })()
  }

  identityKeyPair(): IdentityKeyPair {
    const s = this.get().identityKeyPair
    if (!s) throw new Error('no identity key; run register first')
    return IdentityKeyPair.deserialize(unb64(s))
  }

  /** Forgets consumed one-time prekeys older than the grace period. */
  purgeUsedPreKeys(now = Date.now()): void {
    const used = this.get().usedPreKeys
    for (const [id, e] of Object.entries(used)) if (now - e.usedAt > PREKEY_GRACE_MS) delete used[id]
  }

  /** Drops stored sender keys of `did` for the given distribution ids. */
  forgetSenderKeys(did: string, distributionIds: string[]): void {
    for (const d of distributionIds) delete this.get().senderKeys[`${did}.1|${d}`]
  }
}
