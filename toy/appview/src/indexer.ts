// Relay firehose -> SQLite. Only is.neuros.atsignal.message records are kept.

import { IdResolver } from '@atproto/identity'
import { type Event, Firehose, MemoryRunner } from '@atproto/sync'
import { NSID, config } from '../../shared/src/index.ts'
import { type Db, deleteRecord, getCursor, indexRecord, setCursor } from './db.ts'

export type Indexer = { stop(): Promise<void> }

export function handleEvent(db: Db, evt: Event): void {
  if (evt.event !== 'create' && evt.event !== 'update' && evt.event !== 'delete') return
  if (evt.collection !== NSID.message) return
  if (evt.event === 'delete') {
    if (deleteRecord(db, evt.did, evt.rkey)) console.log(`appview: deleted ${evt.did}/${evt.rkey}`)
    return
  }
  const result = indexRecord(db, { did: evt.did, rkey: evt.rkey, cid: evt.cid.toString(), record: evt.record })
  if (result === 'inserted' || result === 'replaced') console.log(`appview: ${result} ${evt.did}/${evt.rkey}`)
}

export function startIndexer(db: Db, relayUrl: string = config.relayUrl): Indexer {
  // Plain fetch: the default SSRF-safe fetch refuses the local http:// PLC (toy/stack/README.md).
  const idResolver = new IdResolver({ plcUrl: config.plcUrl, fetch: globalThis.fetch })
  // The runner only advances the cursor past an event once it (and every
  // earlier event) has been handled; setCursor persists it so restarts resume.
  const runner = new MemoryRunner({
    startCursor: getCursor(db),
    setCursor: async (seq) => setCursor(db, seq),
  })
  const firehose = new Firehose({
    service: relayUrl,
    idResolver,
    runner,
    filterCollections: [NSID.message],
    handleEvent: (evt) => handleEvent(db, evt),
    onError: (err) => console.error(`appview: firehose error: ${err.message}${err.cause ? ` (${String(err.cause)})` : ''}`),
  })
  void firehose.start()
  console.log(`appview: subscribed to ${relayUrl} (cursor ${getCursor(db) ?? 'none'})`)
  return {
    async stop() {
      await firehose.destroy()
      await runner.destroy()
    },
  }
}
