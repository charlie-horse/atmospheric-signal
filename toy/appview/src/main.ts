import { join, resolve } from 'node:path'
import { config } from '../../shared/src/index.ts'
import { openDb } from './db.ts'
import { startIndexer } from './indexer.ts'
import { closeServer, listen } from './server.ts'

const port = Number(process.env.ATSIG_APPVIEW_PORT ?? 4000)
const dataDir = resolve(process.env.ATSIG_APPVIEW_DATA ?? './data')

const db = openDb(join(dataDir, 'appview.sqlite'))
const server = await listen(db, port)
console.log(`appview: listening on :${port}, data in ${dataDir}`)
const indexer = startIndexer(db, config.relayUrl)

let stopping = false
async function shutdown(signal: string) {
  if (stopping) return
  stopping = true
  console.log(`appview: ${signal}, shutting down`)
  const force = setTimeout(() => process.exit(1), 10_000)
  force.unref()
  try {
    await indexer.stop()
    await closeServer(server)
    db.close()
  } catch (err) {
    console.error('appview: error during shutdown', err)
    process.exitCode = 1
  }
  clearTimeout(force)
}

process.on('SIGINT', () => void shutdown('SIGINT'))
process.on('SIGTERM', () => void shutdown('SIGTERM'))
