// Toy PDS: one in-memory repo per DID, a public firehose, and unauthenticated
// reads, mirroring the ATProto properties the design doc relies on.
// Not modelled: MST, signed commits, CAR files, auth, rate limits.
import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import { lex } from './lexicons.js'

const B32 = '234567abcdefghijklmnopqrstuvwxyz'
let lastTid = 0n
export function tid() {
  // 53-bit microsecond timestamp + 10-bit clock id, base32-sortable, 13 chars
  let us = BigInt(Date.now()) * 1000n
  if (us <= lastTid) us = lastTid + 1n
  lastTid = us
  let n = (us << 10n) | BigInt(randomBytes(2).readUInt16BE() & 0x3ff)
  let s = ''
  for (let i = 0; i < 13; i++) { s = B32[Number(n & 31n)] + s; n >>= 5n }
  return s
}

export class Pds extends EventEmitter {
  constructor() { super(); this.repos = new Map(); this.seq = 0 }

  createAccount(did) { this.repos.set(did, new Map()) }

  #repo(did) {
    const r = this.repos.get(did)
    if (!r) throw new Error(`no repo for ${did}`)
    return r
  }

  // Authenticated as `did` (the toy trusts the caller).
  putRecord(did, collection, rkey, record) {
    const value = { $type: collection, ...record }
    lex.assertValidRecord(collection, value) // reject anything off-schema
    rkey ??= tid()
    this.#repo(did).set(`${collection}/${rkey}`, value)
    this.emit('commit', { seq: ++this.seq, did, op: 'create', collection, rkey, record: value })
    return { did, collection, rkey }
  }

  deleteRecord(did, collection, rkey) {
    this.#repo(did).delete(`${collection}/${rkey}`)
    this.emit('commit', { seq: ++this.seq, did, op: 'delete', collection, rkey })
  }

  // Unauthenticated, like com.atproto.sync.getRepo / repo.getRecord.
  getRecord(did, collection, rkey) { return this.#repo(did).get(`${collection}/${rkey}`) ?? null }

  listRecords(did, collection) {
    return [...this.#repo(did)]
      .filter(([k]) => k.startsWith(collection + '/'))
      .map(([k, value]) => ({ rkey: k.slice(collection.length + 1), value }))
  }

  getRepo(did) { return [...this.#repo(did)].map(([k, value]) => ({ path: k, value })) }
}

// Toy AppView: consumes the firehose and indexes message records by tag.
// It keeps every body it saw, including ones later deleted (design doc §5).
export class TagIndexer {
  constructor(pds, collection) {
    this.byTag = new Map()
    this.archive = new Map()
    pds.on('commit', (e) => {
      if (e.collection !== collection) return
      const key = `${e.did}/${e.rkey}`
      if (e.op === 'create') {
        this.archive.set(key, e.record)
        const t = Buffer.from(e.record.tag).toString('hex')
        if (!this.byTag.has(t)) this.byTag.set(t, [])
        this.byTag.get(t).push({ did: e.did, collection, rkey: e.rkey })
      }
    })
  }
  lookup(tag) { return this.byTag.get(Buffer.from(tag).toString('hex')) ?? [] }
}
