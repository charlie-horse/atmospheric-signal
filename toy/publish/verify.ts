// Acts like a lexicon resolver against a published site.
// Usage: tsx verify.ts <baseUrl> [--skip-dns]
//   baseUrl    e.g. https://atsignal.neuros.is or http://127.0.0.1:8787
//   --skip-dns don't fail on a missing/incorrect _lexicon TXT record (local runs before DNS exists)
import { isDeepStrictEqual } from 'node:util'
import { Lexicons, parseLexiconDoc, type LexiconDoc } from '@atproto/lexicon'
import { buildLexiconResolver } from '@atproto/lexicon-resolver'
import { MemoryBlockstore, def as repoDef, readCarWithRoot, verifyCommitSig, verifyRecords } from '@atproto/repo'
import { DID, HOST, SCHEMA_NSID, loadLexicons } from './build.ts'

const args = process.argv.slice(2)
const base = args.find((a) => !a.startsWith('--'))?.replace(/\/$/, '')
const skipDns = args.includes('--skip-dns')
if (!base) {
  console.error('usage: tsx verify.ts <baseUrl> [--skip-dns]')
  process.exit(2)
}
const isLive = base === `https://${HOST}`

let failures = 0
const ok = (msg: string) => console.log(`  ok    ${msg}`)
const fail = (msg: string) => {
  failures++
  console.log(`  FAIL  ${msg}`)
}
const warn = (msg: string) => console.log(`  warn  ${msg}`)
const errChain = (e: unknown): string => {
  const parts: string[] = []
  for (let c: any = e; c; c = c.cause) parts.push(c.message ?? String(c))
  return parts.join(' <- ')
}

async function get(url: string, headers: Record<string, string> = {}): Promise<Response> {
  const res = await fetch(url, { redirect: 'follow', headers })
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`)
  return res
}

// 1. DNS authority via DoH
console.log(`[1] _lexicon.${HOST} TXT (DoH)`)
try {
  const res = await get(`https://cloudflare-dns.com/dns-query?name=_lexicon.${HOST}&type=TXT`, {
    accept: 'application/dns-json',
  })
  const body = (await res.json()) as { Answer?: { type: number; data: string }[] }
  const txts = (body.Answer ?? [])
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/^"|"$/g, '').replace(/" "/g, ''))
  const dids = txts.filter((t) => t.startsWith('did=')).map((t) => t.slice(4))
  if (dids.length === 1 && dids[0] === DID) ok(`did=${dids[0]}`)
  else (skipDns ? warn : fail)(`expected exactly one did=${DID}, got ${JSON.stringify(txts)}`)
} catch (e) {
  ;(skipDns ? warn : fail)(`DoH lookup failed: ${errChain(e)}`)
}

// 2. DID document
console.log(`[2] ${base}/.well-known/did.json`)
let didKey: string | undefined
try {
  const doc = (await (await get(`${base}/.well-known/did.json`)).json()) as any
  if (doc.id !== DID) fail(`id is ${doc.id}`)
  const vm = (doc.verificationMethod ?? []).find(
    (m: any) => (m.id === '#atproto' || m.id === `${DID}#atproto`) && m.type === 'Multikey',
  )
  if (vm?.controller === DID && typeof vm.publicKeyMultibase === 'string') {
    didKey = `did:key:${vm.publicKeyMultibase}`
    ok(`signing key ${vm.publicKeyMultibase}`)
  } else fail('no #atproto Multikey verification method')
  const pds = (doc.service ?? []).find(
    (s: any) => (s.id === '#atproto_pds' || s.id === `${DID}#atproto_pds`) && s.type === 'AtprotoPersonalDataServer',
  )
  if (pds?.serviceEndpoint === `https://${HOST}`) ok(`pds ${pds.serviceEndpoint}`)
  else fail(`pds service is ${JSON.stringify(pds)}`)
  if (doc.alsoKnownAs?.[0] === `at://${HOST}`) ok(`alsoKnownAs ${doc.alsoKnownAs[0]}`)
  else fail(`alsoKnownAs is ${JSON.stringify(doc.alsoKnownAs)}`)
  const handleDid = (await (await get(`${base}/.well-known/atproto-did`)).text()).trim()
  if (handleDid === DID) ok('.well-known/atproto-did matches')
  else fail(`.well-known/atproto-did is ${handleDid}`)
} catch (e) {
  fail(errChain(e))
}

// 3. Record proofs
console.log(`[3] com.atproto.sync.getRecord proofs`)
const expected = await loadLexicons()
const published: LexiconDoc[] = []
if (didKey) {
  for (const local of expected) {
    const nsid = local.id
    const url =
      `${base}/xrpc/com.atproto.sync.getRecord?did=${encodeURIComponent(DID)}` +
      `&collection=${SCHEMA_NSID}&rkey=${encodeURIComponent(nsid)}`
    try {
      const car = new Uint8Array(await (await get(url)).arrayBuffer())
      const { root, blocks } = await readCarWithRoot(car)
      const commit = await new MemoryBlockstore(blocks).readObj(root, repoDef.commit)
      if (commit.did !== DID) throw new Error(`commit did is ${commit.did}`)
      if (!(await verifyCommitSig(commit, didKey))) throw new Error('commit signature invalid')
      const claims = await verifyRecords(car, DID, didKey) // re-verifies sig + MST inclusion
      const claim = claims.find((c) => c.collection === SCHEMA_NSID && c.rkey === nsid)
      if (!claim?.record) throw new Error('record not in proof')
      const { $type, ...doc } = claim.record as Record<string, unknown>
      if ($type !== SCHEMA_NSID) throw new Error(`$type is ${String($type)}`)
      if (doc.id !== nsid) throw new Error(`record id ${String(doc.id)} != rkey`)
      const parsed = parseLexiconDoc(doc)
      published.push(parsed)
      const same = isDeepStrictEqual(JSON.parse(JSON.stringify(doc)), JSON.parse(JSON.stringify(local)))
      ok(`${nsid} (rev ${commit.rev}, sig ok${same ? ', matches repo file' : ''})`)
      if (!same) warn(`${nsid} differs from lexicons/ in the repo (site is stale; rebuild)`)
    } catch (e) {
      fail(`${nsid}: ${errChain(e)}`)
    }
  }
  try {
    new Lexicons(structuredClone(published)) // it rewrites refs in place
    if (published.length === expected.length) ok(`all ${published.length} lexicons load together`)
  } catch (e) {
    fail(`Lexicons(): ${errChain(e)}`)
  }
} else fail('skipped: no signing key')

// 4. @atproto/lexicon-resolver (informational)
console.log(`[4] @atproto/lexicon-resolver`)
const probe = 'is.neuros.atsignal.message'
async function tryResolver(label: string, resolver: ReturnType<typeof buildLexiconResolver>, opts = {}) {
  try {
    const r = await resolver(probe, opts)
    console.log(`  info  ${label}: resolved ${r.uri.toString()} cid ${r.cid.toString()} rev ${r.commit.rev}`)
    return true
  } catch (e) {
    console.log(`  info  ${label}: ${errChain(e)}`)
    return false
  }
}
// GitHub Pages can't set Content-Type on extensionless files, so getRecord comes back as
// application/octet-stream; the resolver insists on application/vnd.ipld.car.
const carFetch: typeof fetch = async (input, init) => {
  const res = await fetch(input, init)
  if (!new URL(res.url).pathname.endsWith('/com.atproto.sync.getRecord')) return res
  const headers = new Headers(res.headers)
  headers.set('content-type', 'application/vnd.ipld.car')
  return new Response(await res.arrayBuffer(), { status: res.status, headers })
}
if (isLive) {
  // Fully network-driven: DNS (node resolver) -> did:web -> PDS getRecord.
  const plain = await tryResolver('resolveLexicon', buildLexiconResolver())
  if (!plain) await tryResolver('with content-type fixup', buildLexiconResolver({ rpc: { fetch: carFetch } }))
} else {
  // Local: inject the DID doc we fetched and point the RPC at the local base URL.
  const doc = await (await get(`${base}/.well-known/did.json`)).json()
  const idResolver = { did: { ensureResolve: async () => doc } } as any
  const opts = { didAuthority: DID } as const
  const plain = await tryResolver('resolveLexicon', buildLexiconResolver({ idResolver, rpc: { service: base, fetch } }), opts)
  if (!plain) await tryResolver('with content-type fixup', buildLexiconResolver({ idResolver, rpc: { service: base, fetch: carFetch } }), opts)
}

console.log(failures ? `\nFAILED (${failures})` : '\nPASS')
process.exit(failures ? 1 : 0)
