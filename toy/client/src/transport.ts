// PDS and AppView I/O behind one interface, so the crypto/state layer can run
// against an in-memory network in tests (and later against Spaces).

import { randomBytes } from 'node:crypto'
import { AtpAgent } from '@atproto/api'
import { NSID, config, resolveDid, resolveHandle, tagToParam } from '../../shared/src/index.ts'

export type RepoRecord = { rkey: string; value: Record<string, unknown> }

/** One AppView messageView, with bytes decoded. */
export type MessageView = {
  did: string
  rkey: string
  cid?: string
  tag: Uint8Array
  envelopeType: string
  ciphertext: Uint8Array
  indexedAt: string
}

export interface Transport {
  /** Logs in; if that fails, creates the account. Returns the account DID. */
  createOrLogin(handle: string, password: string, email: string): Promise<{ did: string; created: boolean }>
  /** Logs in to an existing account. Returns the account DID. */
  login(handle: string, password: string): Promise<{ did: string }>
  /** Own repo writes (require login). */
  createRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void>
  putRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void>
  deleteRecord(collection: string, rkey: string): Promise<void>
  /** Public reads of any repo. */
  listRecords(did: string, collection: string): Promise<RepoRecord[]>
  getRecord(did: string, collection: string, rkey: string): Promise<Record<string, unknown> | null>
  /** Handle (or DID, returned unchanged) to DID. */
  resolveDid(handleOrDid: string): Promise<string>
  /** AppView query; at most 50 tags. */
  getMessagesByTag(tags: Uint8Array[], cursor?: string, limit?: number): Promise<{ cursor?: string; messages: MessageView[] }>
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e))
const stripSlash = (u: string): string => u.replace(/\/+$/, '')

function decodeBytesField(v: unknown, name: string): Uint8Array {
  if (v instanceof Uint8Array) return v
  if (v && typeof v === 'object' && typeof (v as { $bytes?: unknown }).$bytes === 'string') {
    return new Uint8Array(Buffer.from((v as { $bytes: string }).$bytes, 'base64'))
  }
  throw new Error(`messageView.${name} is not bytes`)
}

/** Real transport: own PDS at config.pdsUrl, other repos via DID resolution, AppView at config.appviewUrl. */
export class AtprotoTransport implements Transport {
  private readonly agent = new AtpAgent({ service: config.pdsUrl })
  private readonly readAgents = new Map<string, AtpAgent>()

  private get did(): string {
    const did = this.agent.session?.did
    if (!did) throw new Error('not logged in')
    return did
  }

  async login(handle: string, password: string): Promise<{ did: string }> {
    await this.agent.login({ identifier: handle, password })
    return { did: this.did }
  }

  async createOrLogin(handle: string, password: string, email: string): Promise<{ did: string; created: boolean }> {
    try {
      return { ...(await this.login(handle, password)), created: false }
    } catch (loginErr) {
      try {
        await this.agent.createAccount({ handle, email, password, inviteCode: process.env.ATSIG_INVITE_CODE || undefined })
        return { did: this.did, created: true }
      } catch (createErr) {
        throw new Error(`login failed (${errMsg(loginErr)}) and createAccount failed (${errMsg(createErr)})`)
      }
    }
  }

  async createRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void> {
    await this.agent.com.atproto.repo.createRecord({ repo: this.did, collection, rkey, record })
  }

  async putRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void> {
    await this.agent.com.atproto.repo.putRecord({ repo: this.did, collection, rkey, record })
  }

  async deleteRecord(collection: string, rkey: string): Promise<void> {
    await this.agent.com.atproto.repo.deleteRecord({ repo: this.did, collection, rkey })
  }

  private async readAgent(did: string): Promise<AtpAgent> {
    let a = this.readAgents.get(did)
    if (!a) {
      const { pdsUrl } = await resolveDid(did)
      a = new AtpAgent({ service: pdsUrl })
      this.readAgents.set(did, a)
    }
    return a
  }

  async listRecords(did: string, collection: string): Promise<RepoRecord[]> {
    const agent = await this.readAgent(did)
    const out: RepoRecord[] = []
    let cursor: string | undefined
    do {
      const res = await agent.com.atproto.repo.listRecords({ repo: did, collection, limit: 100, cursor })
      for (const r of res.data.records) {
        out.push({ rkey: r.uri.split('/').pop()!, value: r.value as Record<string, unknown> })
      }
      cursor = res.data.records.length > 0 ? res.data.cursor : undefined
    } while (cursor)
    return out
  }

  async getRecord(did: string, collection: string, rkey: string): Promise<Record<string, unknown> | null> {
    const agent = await this.readAgent(did)
    try {
      const res = await agent.com.atproto.repo.getRecord({ repo: did, collection, rkey })
      return res.data.value as Record<string, unknown>
    } catch (e) {
      const x = e as { error?: string; status?: number }
      if (x.error === 'RecordNotFound' || x.status === 404 || /not ?found|could not locate/i.test(errMsg(e))) return null
      throw e
    }
  }

  async resolveDid(handleOrDid: string): Promise<string> {
    const s = handleOrDid.replace(/^@/, '')
    return s.startsWith('did:') ? s : resolveHandle(s)
  }

  async getMessagesByTag(tags: Uint8Array[], cursor?: string, limit = 100) {
    const params = new URLSearchParams()
    for (const t of tags) params.append('tags', tagToParam(t))
    if (cursor) params.set('cursor', cursor)
    params.set('limit', String(limit))
    const url = `${stripSlash(config.appviewUrl)}/xrpc/${NSID.getMessagesByTag}?${params}`
    const res = await fetch(url)
    if (!res.ok) throw new Error(`getMessagesByTag: HTTP ${res.status} ${await res.text()}`)
    const body = (await res.json()) as { cursor?: string; messages: Array<Record<string, unknown>> }
    return {
      cursor: body.cursor,
      messages: body.messages.map((m) => ({
        did: String(m.did),
        rkey: String(m.rkey),
        cid: m.cid === undefined ? undefined : String(m.cid),
        tag: decodeBytesField(m.tag, 'tag'),
        envelopeType: String(m.envelopeType),
        ciphertext: decodeBytesField(m.ciphertext, 'ciphertext'),
        indexedAt: String(m.indexedAt),
      })),
    }
  }
}

// ---------------------------------------------------------------------------
// In-memory network for tests: accounts, repos and a tag index in one object.

type Repo = Map<string, Map<string, Record<string, unknown>>>

export class MemoryNetwork {
  readonly accounts = new Map<string, { did: string; password: string }>()
  readonly repos = new Map<string, Repo>()
  /** The AppView index: every message record ever created, in order. Deletions don't remove entries. */
  readonly index: Array<{ seq: number; view: MessageView }> = []
  private seq = 0

  transport(): MemoryTransport {
    return new MemoryTransport(this)
  }

  repo(did: string): Repo {
    let r = this.repos.get(did)
    if (!r) this.repos.set(did, (r = new Map()))
    return r
  }

  write(did: string, collection: string, rkey: string, record: Record<string, unknown>, create: boolean): void {
    const repo = this.repo(did)
    let coll = repo.get(collection)
    if (!coll) repo.set(collection, (coll = new Map()))
    if (create && coll.has(rkey)) throw new Error(`record exists: ${collection}/${rkey}`)
    coll.set(rkey, record)
    if (collection === NSID.message) {
      this.index.push({
        seq: ++this.seq,
        view: {
          did,
          rkey,
          tag: record.tag as Uint8Array,
          envelopeType: record.envelopeType as string,
          ciphertext: record.ciphertext as Uint8Array,
          indexedAt: new Date().toISOString(),
        },
      })
    }
  }
}

export class MemoryTransport implements Transport {
  private did?: string
  constructor(readonly net: MemoryNetwork) {}

  private me(): string {
    if (!this.did) throw new Error('not logged in')
    return this.did
  }

  async login(handle: string, password: string): Promise<{ did: string }> {
    const a = this.net.accounts.get(handle)
    if (!a || a.password !== password) throw new Error('AuthenticationRequired: invalid identifier or password')
    this.did = a.did
    return { did: a.did }
  }

  async createOrLogin(handle: string, password: string, _email: string): Promise<{ did: string; created: boolean }> {
    if (this.net.accounts.has(handle)) return { ...(await this.login(handle, password)), created: false }
    const did = `did:plc:${randomBytes(12).toString('hex')}`
    this.net.accounts.set(handle, { did, password })
    this.did = did
    return { did, created: true }
  }

  async createRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void> {
    this.net.write(this.me(), collection, rkey, record, true)
  }

  async putRecord(collection: string, rkey: string, record: Record<string, unknown>): Promise<void> {
    this.net.write(this.me(), collection, rkey, record, false)
  }

  async deleteRecord(collection: string, rkey: string): Promise<void> {
    this.net.repo(this.me()).get(collection)?.delete(rkey)
  }

  async listRecords(did: string, collection: string): Promise<RepoRecord[]> {
    const coll = this.net.repo(did).get(collection)
    return coll ? [...coll].map(([rkey, value]) => ({ rkey, value })) : []
  }

  async getRecord(did: string, collection: string, rkey: string): Promise<Record<string, unknown> | null> {
    return this.net.repo(did).get(collection)?.get(rkey) ?? null
  }

  async resolveDid(handleOrDid: string): Promise<string> {
    if (handleOrDid.startsWith('did:')) return handleOrDid
    const a = this.net.accounts.get(handleOrDid.replace(/^@/, ''))
    if (!a) throw new Error(`unknown handle ${handleOrDid}`)
    return a.did
  }

  async getMessagesByTag(tags: Uint8Array[], cursor?: string, limit = 100) {
    if (tags.length === 0 || tags.length > 50) throw new Error('tags: 1..50 required')
    const want = new Set(tags.map(tagToParam))
    const after = cursor ? Number(cursor) : 0
    const hits = this.net.index.filter((e) => e.seq > after && want.has(tagToParam(e.view.tag))).slice(0, limit)
    return {
      cursor: hits.length ? String(hits[hits.length - 1]!.seq) : cursor,
      messages: hits.map((e) => e.view),
    }
  }
}
