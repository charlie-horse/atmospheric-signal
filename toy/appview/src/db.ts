// SQLite storage for indexed message records and the relay cursor.
// The AppView stores what is public in the record (author DID, rkey, CID, tag,
// envelope type, ciphertext). It never stores or derives a recipient.

import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { NSID, lexicons } from '../../shared/src/index.ts'

export type Db = DatabaseSync

export type MessageRow = {
  id: number
  did: string
  rkey: string
  cid: string
  tag: Uint8Array
  envelopeType: string
  ciphertext: Uint8Array
  indexedAt: string
}

export type IndexInput = {
  did: string
  rkey: string
  cid: string
  record: unknown
}

export type IndexResult = 'inserted' | 'replaced' | 'unchanged' | 'invalid'

export function openDb(path: string): Db {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
  const db = new DatabaseSync(path)
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS message (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT NOT NULL,
      rkey TEXT NOT NULL,
      cid TEXT NOT NULL,
      tag BLOB NOT NULL,
      envelope_type TEXT NOT NULL,
      ciphertext BLOB NOT NULL,
      indexed_at TEXT NOT NULL,
      UNIQUE(did, rkey)
    );
    CREATE INDEX IF NOT EXISTS message_tag_idx ON message(tag, id);
    CREATE TABLE IF NOT EXISTS kv (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `)
  return db
}

/**
 * Validate an is.neuros.atsignal.message record and upsert it.
 * - Invalid records are dropped (and any older version at the same rkey is
 *   removed, since it is no longer the record's current value).
 * - Re-delivery of the same CID is a no-op (keeps the row id, so replayed
 *   firehose events do not re-surface old messages).
 * - A new CID at an existing rkey replaces the row with a fresh id, so it is
 *   "indexed after" any cursor a client already holds.
 */
export function indexRecord(db: Db, input: IndexInput, log: (msg: string) => void = console.warn): IndexResult {
  const { did, rkey, cid, record } = input
  try {
    lexicons.assertValidRecord(NSID.message, record)
  } catch (err) {
    log(`appview: dropping invalid ${NSID.message} record ${did}/${rkey} (${cid}): ${(err as Error).message}`)
    deleteRecord(db, did, rkey)
    return 'invalid'
  }
  const rec = record as { tag: Uint8Array; envelopeType: string; ciphertext: Uint8Array }

  const existing = db.prepare('SELECT cid FROM message WHERE did = ? AND rkey = ?').get(did, rkey) as
    | { cid: string }
    | undefined
  if (existing?.cid === cid) return 'unchanged'

  const indexedAt = new Date().toISOString()
  db.exec('BEGIN')
  try {
    if (existing) deleteRecord(db, did, rkey)
    db.prepare(
      `INSERT INTO message (did, rkey, cid, tag, envelope_type, ciphertext, indexed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(did, rkey, cid, rec.tag, rec.envelopeType, rec.ciphertext, indexedAt)
    db.exec('COMMIT')
  } catch (err) {
    db.exec('ROLLBACK')
    throw err
  }
  return existing ? 'replaced' : 'inserted'
}

/** Deletion = remove access: the row is gone and will not be served again. */
export function deleteRecord(db: Db, did: string, rkey: string): boolean {
  const res = db.prepare('DELETE FROM message WHERE did = ? AND rkey = ?').run(did, rkey)
  return Number(res.changes) > 0
}

/** Messages with any of the given tags and id > afterId, oldest first. */
export function queryByTags(db: Db, tags: Uint8Array[], afterId: number, limit: number): MessageRow[] {
  if (tags.length === 0) return []
  const placeholders = tags.map(() => '?').join(', ')
  const rows = db
    .prepare(
      `SELECT id, did, rkey, cid, tag, envelope_type, ciphertext, indexed_at
       FROM message WHERE tag IN (${placeholders}) AND id > ?
       ORDER BY id ASC LIMIT ?`,
    )
    .all(...tags, afterId, limit) as Array<{
    id: number
    did: string
    rkey: string
    cid: string
    tag: Uint8Array
    envelope_type: string
    ciphertext: Uint8Array
    indexed_at: string
  }>
  return rows.map((r) => ({
    id: r.id,
    did: r.did,
    rkey: r.rkey,
    cid: r.cid,
    tag: r.tag,
    envelopeType: r.envelope_type,
    ciphertext: r.ciphertext,
    indexedAt: r.indexed_at,
  }))
}

export function countMessages(db: Db): number {
  const row = db.prepare('SELECT COUNT(*) AS n FROM message').get() as { n: number }
  return Number(row.n)
}

export function getCursor(db: Db): number | undefined {
  const row = db.prepare(`SELECT value FROM kv WHERE key = 'relaySeq'`).get() as { value: string } | undefined
  return row ? Number(row.value) : undefined
}

export function setCursor(db: Db, seq: number): void {
  db.prepare(
    `INSERT INTO kv (key, value) VALUES ('relaySeq', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).run(String(seq))
}
