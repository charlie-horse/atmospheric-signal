import assert from 'node:assert/strict'
import type http from 'node:http'
import { after, before, beforeEach, describe, test } from 'node:test'
import { NSID, tagToParam } from '../../shared/src/index.ts'
import { type Db, countMessages, getCursor, indexRecord, openDb, setCursor } from '../src/db.ts'
import { handleEvent } from '../src/indexer.ts'
import { closeServer, listen, serverPort } from '../src/server.ts'

const ALICE = 'did:plc:aliceaaaaaaaaaaaaaaaaaaa'
const BOB = 'did:plc:bobbbbbbbbbbbbbbbbbbbbbb'
const CID_A = 'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm'
const CID_B = 'bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a'

const quiet = () => {}

// ATProto JSON $bytes: standard base64 alphabet, no padding.
function b64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64').replace(/=+$/, '')
}

function bytes(len: number, fill: number): Uint8Array {
  return new Uint8Array(len).fill(fill)
}

let rkeyCounter = 0
function nextRkey(): string {
  // Valid TID-shaped record keys, increasing.
  rkeyCounter++
  return `3l${rkeyCounter.toString(32).padStart(11, '2')}`
}

function message(tag: Uint8Array, ciphertext: Uint8Array, envelopeType = 'whisper') {
  return { $type: NSID.message, tag, envelopeType, ciphertext, formatVersion: 1 }
}

type MessageViewJson = {
  did: string
  rkey: string
  cid: string
  tag: { $bytes: string }
  envelopeType: string
  ciphertext: { $bytes: string }
  indexedAt: string
}
type Output = { cursor?: string; messages: MessageViewJson[] }

describe('appview', () => {
  let db: Db
  let server: http.Server
  let base: string

  before(async () => {
    db = openDb(':memory:')
    server = await listen(db, 0, '127.0.0.1')
    base = `http://127.0.0.1:${serverPort(server)}`
  })

  after(async () => {
    await closeServer(server)
    db.close()
  })

  beforeEach(() => {
    db.exec('DELETE FROM message; DELETE FROM kv;')
  })

  async function query(tags: Uint8Array[], extra: Record<string, string> = {}): Promise<{ status: number; body: any }> {
    const qs = new URLSearchParams()
    for (const t of tags) qs.append('tags', tagToParam(t))
    for (const [k, v] of Object.entries(extra)) qs.set(k, v)
    const res = await fetch(`${base}/xrpc/${NSID.getMessagesByTag}?${qs}`)
    return { status: res.status, body: await res.json() }
  }

  test('indexes a record and serves it by tag with $bytes encoding', async () => {
    const tag = bytes(16, 1)
    const ct = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xff])
    const rkey = nextRkey()
    assert.equal(indexRecord(db, { did: ALICE, rkey, cid: CID_A, record: message(tag, ct, 'prekey') }, quiet), 'inserted')

    const { status, body } = await query([tag])
    assert.equal(status, 200)
    const out = body as Output
    assert.equal(out.messages.length, 1)
    const m = out.messages[0]
    assert.equal(m.did, ALICE)
    assert.equal(m.rkey, rkey)
    assert.equal(m.cid, CID_A)
    assert.equal(m.envelopeType, 'prekey')
    assert.deepEqual(m.tag, { $bytes: b64(tag) })
    assert.deepEqual(m.ciphertext, { $bytes: b64(ct) })
    assert.ok(!m.tag.$bytes.includes('='), 'no padding')
    assert.ok(!Number.isNaN(Date.parse(m.indexedAt)))
    assert.equal(Object.keys(m).sort().join(','), 'cid,ciphertext,did,envelopeType,indexedAt,rkey,tag')
    assert.match(out.cursor!, /^\d+$/)
  })

  test('filters by tag, accepts repeated tags, returns oldest first', async () => {
    const t1 = bytes(16, 1)
    const t2 = bytes(16, 2)
    const t3 = bytes(32, 3)
    indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record: message(t1, bytes(4, 10)) }, quiet)
    indexRecord(db, { did: BOB, rkey: nextRkey(), cid: CID_A, record: message(t2, bytes(4, 11)) }, quiet)
    indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record: message(t3, bytes(4, 12)) }, quiet)
    indexRecord(db, { did: BOB, rkey: nextRkey(), cid: CID_A, record: message(t1, bytes(4, 13)) }, quiet)

    const one = (await query([t1])).body as Output
    assert.deepEqual(
      one.messages.map((m) => m.ciphertext.$bytes),
      [bytes(4, 10), bytes(4, 13)].map(b64),
    )

    const many = (await query([t3, t1])).body as Output
    assert.deepEqual(
      many.messages.map((m) => Buffer.from(m.ciphertext.$bytes, 'base64')[0]),
      [10, 12, 13],
    )

    const none = (await query([bytes(16, 9)])).body as Output
    assert.deepEqual(none.messages, [])
    assert.equal(none.cursor, undefined)
  })

  test('cursor paging', async () => {
    const tag = bytes(16, 5)
    for (let i = 0; i < 7; i++) {
      indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record: message(tag, bytes(3, i)) }, quiet)
    }
    const seen: number[] = []
    let cursor: string | undefined
    let pages = 0
    for (;;) {
      const { body } = await query([tag], { limit: '3', ...(cursor ? { cursor } : {}) })
      const out = body as Output
      pages++
      if (out.messages.length === 0) {
        assert.equal(out.cursor, cursor, 'empty page echoes the cursor back')
        break
      }
      assert.ok(out.messages.length <= 3)
      seen.push(...out.messages.map((m) => Buffer.from(m.ciphertext.$bytes, 'base64')[0]))
      cursor = out.cursor
    }
    assert.deepEqual(seen, [0, 1, 2, 3, 4, 5, 6])
    assert.equal(pages, 4)

    // New messages after the cursor show up on the next poll.
    indexRecord(db, { did: BOB, rkey: nextRkey(), cid: CID_A, record: message(tag, bytes(3, 42)) }, quiet)
    const next = (await query([tag], { cursor: cursor! })).body as Output
    assert.equal(next.messages.length, 1)
    assert.equal(Buffer.from(next.messages[0].ciphertext.$bytes, 'base64')[0], 42)
  })

  test('default limit is 50 and limit > 100 is rejected', async () => {
    const tag = bytes(16, 6)
    for (let i = 0; i < 60; i++) {
      indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record: message(tag, bytes(2, i)) }, quiet)
    }
    assert.equal(((await query([tag])).body as Output).messages.length, 50)
    const tooMany = await query([tag], { limit: '101' })
    assert.equal(tooMany.status, 400)
    assert.equal(tooMany.body.error, 'InvalidRequest')
  })

  test('bad params are rejected', async () => {
    const missing = await fetch(`${base}/xrpc/${NSID.getMessagesByTag}`)
    assert.equal(missing.status, 400)
    const badTag = await fetch(`${base}/xrpc/${NSID.getMessagesByTag}?tags=${encodeURIComponent('not+base64/')}`)
    assert.equal(badTag.status, 400)
    const badCursor = await query([bytes(16, 1)], { cursor: 'abc' })
    assert.equal(badCursor.status, 400)
  })

  test('firehose create then delete (deletion = remove access)', async () => {
    const tag = bytes(16, 7)
    const rkey = nextRkey()
    handleEvent(db, {
      event: 'create',
      did: ALICE,
      collection: NSID.message,
      rkey,
      cid: { toString: () => CID_A },
      record: message(tag, bytes(4, 1)),
    } as unknown as Parameters<typeof handleEvent>[1])
    // Other collections are ignored even if they reach the handler.
    handleEvent(db, {
      event: 'create',
      did: ALICE,
      collection: NSID.preKey,
      rkey: nextRkey(),
      cid: { toString: () => CID_A },
      record: message(tag, bytes(4, 2)),
    } as unknown as Parameters<typeof handleEvent>[1])
    const before = (await query([tag])).body as Output
    assert.equal(before.messages.length, 1)
    assert.equal(before.messages[0].cid, CID_A)

    handleEvent(db, {
      event: 'delete',
      did: ALICE,
      collection: NSID.message,
      rkey,
    } as unknown as Parameters<typeof handleEvent>[1])
    assert.equal(((await query([tag])).body as Output).messages.length, 0)
    assert.equal(countMessages(db), 0)
  })

  test('update with a new CID replaces the row with a fresh id; same CID is a no-op', async () => {
    const tag = bytes(16, 8)
    const rkey = nextRkey()
    indexRecord(db, { did: ALICE, rkey, cid: CID_A, record: message(tag, bytes(4, 1)) }, quiet)
    const first = (await query([tag])).body as Output
    assert.equal(indexRecord(db, { did: ALICE, rkey, cid: CID_A, record: message(tag, bytes(4, 1)) }, quiet), 'unchanged')
    assert.equal(indexRecord(db, { did: ALICE, rkey, cid: CID_B, record: message(tag, bytes(4, 2)) }, quiet), 'replaced')
    const after = (await query([tag], { cursor: first.cursor! })).body as Output
    assert.equal(after.messages.length, 1)
    assert.equal(after.messages[0].cid, CID_B)
    assert.equal(countMessages(db), 1)
  })

  test('invalid records are rejected', () => {
    const logs: string[] = []
    const log = (m: string) => logs.push(m)
    const ok = message(bytes(16, 1), bytes(4, 1))
    const cases: unknown[] = [
      { ...ok, tag: bytes(8, 1) }, // 8-byte tag, below minLength 16
      { ...ok, tag: bytes(33, 1) }, // above maxLength 32
      { ...ok, ciphertext: new Uint8Array(0) },
      { ...ok, formatVersion: 0 },
      { ...ok, $type: NSID.preKey },
      { tag: ok.tag, envelopeType: 'whisper', ciphertext: ok.ciphertext, formatVersion: 1 }, // no $type
      { ...ok, tag: Buffer.from(ok.tag).toString('base64') }, // string, not bytes
    ]
    for (const record of cases) {
      assert.equal(indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record }, log), 'invalid')
    }
    assert.equal(countMessages(db), 0)
    assert.equal(logs.length, cases.length)
    assert.match(logs[0], /dropping invalid/)
  })

  test('an invalid update removes the previously indexed version', () => {
    const rkey = nextRkey()
    indexRecord(db, { did: ALICE, rkey, cid: CID_A, record: message(bytes(16, 1), bytes(4, 1)) }, quiet)
    assert.equal(countMessages(db), 1)
    indexRecord(db, { did: ALICE, rkey, cid: CID_B, record: message(bytes(8, 1), bytes(4, 1)) }, quiet)
    assert.equal(countMessages(db), 0)
  })

  test('/health reports count and relay cursor', async () => {
    let res = await fetch(`${base}/health`)
    assert.equal(res.status, 200)
    assert.deepEqual(await res.json(), { ok: true, indexed: 0, lastSeq: null })

    indexRecord(db, { did: ALICE, rkey: nextRkey(), cid: CID_A, record: message(bytes(16, 1), bytes(4, 1)) }, quiet)
    setCursor(db, 1234)
    assert.equal(getCursor(db), 1234)
    res = await fetch(`${base}/health`)
    assert.deepEqual(await res.json(), { ok: true, indexed: 1, lastSeq: 1234 })
  })

  test('the store has no recipient column', () => {
    const cols = (db.prepare('PRAGMA table_info(message)').all() as Array<{ name: string }>).map((c) => c.name)
    assert.deepEqual(cols, ['id', 'did', 'rkey', 'cid', 'tag', 'envelope_type', 'ciphertext', 'indexed_at'])
  })
})
