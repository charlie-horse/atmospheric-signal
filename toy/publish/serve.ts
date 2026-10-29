// Tiny static server for ./site that behaves like GitHub Pages for our purposes:
// query strings are ignored, extensionless files are application/octet-stream.
// Usage: tsx serve.ts [port]
import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import { dirname, extname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const SITE = join(dirname(fileURLToPath(import.meta.url)), 'site')
const port = Number(process.argv[2] ?? 8787)
const TYPES: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.json': 'application/json' }

createServer(async (req, res) => {
  let path = normalize(decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname))
  if (path.endsWith('/')) path += 'index.html'
  const file = join(SITE, path)
  if (!file.startsWith(SITE)) return void res.writeHead(400).end()
  try {
    if (!(await stat(file)).isFile()) throw new Error('not a file')
    const body = await readFile(file)
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(body)
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found')
  }
}).listen(port, '127.0.0.1', () => console.log(`serving ${SITE} on http://127.0.0.1:${port}`))
