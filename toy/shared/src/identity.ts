import { config } from './config.ts'

export type ResolvedDid = { did: string; handle?: string; pdsUrl: string; signingKey?: string }

type DidDocument = {
  id?: string
  alsoKnownAs?: unknown
  verificationMethod?: unknown
  service?: unknown
}

const TIMEOUT_MS = 10_000

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: 'application/json' } })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`GET ${url} failed: ${res.status} ${res.statusText} ${body.slice(0, 200)}`.trim())
  }
  return res.json()
}

function stripSlash(url: string): string {
  return url.replace(/\/+$/, '')
}

/** did:web:host%3Aport:path:segs -> https://host:port/path/segs/did.json (or /.well-known/did.json). */
function didWebUrl(did: string): string {
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent)
  const host = parts[0]
  if (!host) throw new Error(`invalid did:web: ${did}`)
  // Toy rule: localhost did:web is served over plain http by the local stack.
  const hostname = host.replace(/:\d+$/, '')
  const scheme = hostname === 'localhost' || hostname === '127.0.0.1' ? 'http' : 'https'
  const path = parts.length > 1 ? `/${parts.slice(1).join('/')}/did.json` : '/.well-known/did.json'
  return `${scheme}://${host}${path}`
}

function matchesId(id: unknown, did: string, frag: string): boolean {
  return id === `#${frag}` || id === `${did}#${frag}`
}

export async function resolveDid(did: string): Promise<ResolvedDid> {
  let url: string
  if (did.startsWith('did:plc:')) url = `${stripSlash(config.plcUrl)}/${did}`
  else if (did.startsWith('did:web:')) url = didWebUrl(did)
  else throw new Error(`unsupported DID method: ${did}`)

  const doc = (await getJson(url)) as DidDocument
  if (!doc || typeof doc !== 'object') throw new Error(`DID document for ${did} is not an object`)
  if (doc.id !== did) throw new Error(`DID document id ${JSON.stringify(doc.id)} does not match ${did}`)

  const services = Array.isArray(doc.service) ? doc.service : []
  const pds = services.find((s) => matchesId(s?.id, did, 'atproto_pds'))
  const endpoint: unknown = pds?.serviceEndpoint
  if (typeof endpoint !== 'string') throw new Error(`DID document for ${did} has no #atproto_pds service`)

  let pdsUrl = stripSlash(endpoint)
  // Toy rule: a local PDS may advertise e.g. https://localhost:3000 in its DID docs
  // while actually serving plain http. If the endpoint's hostname matches the
  // configured PDS, use config.pdsUrl (the URL we know works) instead.
  try {
    if (new URL(endpoint).hostname === new URL(config.pdsUrl).hostname) pdsUrl = stripSlash(config.pdsUrl)
  } catch {
    throw new Error(`DID document for ${did} has an invalid PDS endpoint: ${endpoint}`)
  }

  const aka = Array.isArray(doc.alsoKnownAs) ? doc.alsoKnownAs : []
  const atUri = aka.find((a): a is string => typeof a === 'string' && a.startsWith('at://'))
  const handle = atUri ? atUri.slice('at://'.length) : undefined

  const methods = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []
  const key: unknown = methods.find((m) => matchesId(m?.id, did, 'atproto'))?.publicKeyMultibase
  const signingKey = typeof key === 'string' ? key : undefined

  return { did, handle, pdsUrl, signingKey }
}

/** com.atproto.identity.resolveHandle on config.pdsUrl. Returns the DID. */
export async function resolveHandle(handle: string): Promise<string> {
  const h = handle.replace(/^@/, '').toLowerCase()
  const url = `${stripSlash(config.pdsUrl)}/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(h)}`
  const body = (await getJson(url)) as { did?: unknown }
  if (typeof body?.did !== 'string' || !body.did.startsWith('did:')) {
    throw new Error(`resolveHandle(${handle}) returned no DID`)
  }
  return body.did
}
