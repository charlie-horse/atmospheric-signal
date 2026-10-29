// HTTP: XRPC getMessagesByTag (lexicon-validated params and output) plus /health.

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { InvalidRequestError, createServer as createXrpcServer } from '@atproto/xrpc-server'
import { NSID, loadLexiconDocs, tagFromParam } from '../../shared/src/index.ts'
import { type Db, countMessages, getCursor, queryByTags } from './db.ts'

export const DEFAULT_LIMIT = 50
export const MAX_LIMIT = 100

export function createApp(db: Db): http.RequestListener {
  // validateResponse defaults to on: output is checked against messageView,
  // and xrpc-server serializes it with lexToJson, so bytes become {"$bytes": ...}.
  const xrpc = createXrpcServer(loadLexiconDocs())

  xrpc.method(NSID.getMessagesByTag, {
    handler: ({ params }) => {
      const rawTags = params.tags as string[]
      const tags = rawTags.map((s) => {
        try {
          return tagFromParam(s)
        } catch {
          throw new InvalidRequestError(`tags must be base64url: ${s}`)
        }
      })

      let afterId = 0
      const cursor = params.cursor as string | undefined
      if (cursor !== undefined) {
        if (!/^\d{1,15}$/.test(cursor)) throw new InvalidRequestError('Malformed cursor', 'InvalidCursor')
        afterId = Number(cursor)
      }

      const limit = Math.min((params.limit as number | undefined) ?? DEFAULT_LIMIT, MAX_LIMIT)
      const rows = queryByTags(db, tags, afterId, limit)
      const last = rows.at(-1)

      return {
        encoding: 'application/json',
        body: {
          cursor: last ? String(last.id) : cursor,
          messages: rows.map((r) => ({
            did: r.did,
            rkey: r.rkey,
            cid: r.cid,
            tag: r.tag,
            envelopeType: r.envelopeType,
            ciphertext: r.ciphertext,
            indexedAt: r.indexedAt,
          })),
        },
      }
    },
  })

  const router = xrpc.router as unknown as http.RequestListener

  return (req, res) => {
    const path = (req.url ?? '').split('?')[0]
    if (path === '/health' && (req.method === 'GET' || req.method === 'HEAD')) {
      const lastSeq = getCursor(db) ?? null
      const body = JSON.stringify({ ok: true, indexed: countMessages(db), lastSeq })
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
      res.end(req.method === 'HEAD' ? undefined : body)
      return
    }
    router(req, res)
  }
}

export async function listen(db: Db, port: number, host?: string): Promise<http.Server> {
  const server = http.createServer(createApp(db))
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => {
      server.off('error', reject)
      resolve()
    })
  })
  return server
}

export function serverPort(server: http.Server): number {
  return (server.address() as AddressInfo).port
}

export async function closeServer(server: http.Server): Promise<void> {
  const closed = new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  server.closeAllConnections()
  await closed
}
