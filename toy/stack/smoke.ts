// Smoke test for the local stack: create two accounts on Tranquil, write an
// is.neuros.atsignal.message record, and confirm the relay firehose delivers it
// (signature-verified against the PLC directory by @atproto/sync).
//
//   npx tsx smoke.ts        (stack must be up: ./up.sh)
import { randomBytes } from 'node:crypto'
import { AtpAgent } from '@atproto/api'
import { IdResolver } from '@atproto/identity'
import { Firehose, type Event } from '@atproto/sync'

const plcUrl = process.env.ATSIG_PLC_URL ?? 'http://localhost:2582'
const pdsUrl = process.env.ATSIG_PDS_URL ?? 'http://localhost:3000'
const relayUrl = process.env.ATSIG_RELAY_URL ?? 'ws://localhost:2470'
const HANDLE_DOMAIN = process.env.ATSIG_HANDLE_DOMAIN ?? 'test'
const COLLECTION = 'is.neuros.atsignal.message'
const TIMEOUT_MS = Number(process.env.SMOKE_TIMEOUT_MS ?? 30_000)

const step = (msg: string) => console.log(`[smoke] ${msg}`)
const fail = (msg: string): never => {
  console.error(`[smoke] FAIL: ${msg}`)
  process.exit(1)
}

async function createAccount(name: string) {
  const agent = new AtpAgent({ service: pdsUrl })
  // Handle: short name + "." + handle domain (PDS_USER_HANDLE_DOMAINS=test).
  // Local part: 3-18 chars, [a-z0-9-]. Tranquil also accepts the bare short
  // name and appends the domain itself, but sending the full handle is portable.
  const body = {
    handle: `${name}.${HANDLE_DOMAIN}`,
    email: `${name}@atsig.test`, // required (verification channel defaults to email); never verified
    password: `Atsig-${name}-Pw1`, // Tranquil: >=8 chars with a lowercase, an uppercase and a digit
  }
  const res = await agent.createAccount(body)
  return { agent, did: res.data.did, handle: res.data.handle, body }
}

async function main() {
  const run = randomBytes(3).toString('hex')
  // @atproto/identity >=0.5.x defaults to an SSRF-protected fetch that rejects
  // http:// and loopback URLs, so a local PLC needs a plain fetch passed in.
  const idResolver = new IdResolver({ plcUrl, fetch: globalThis.fetch })

  // 1. Subscribe to the relay *before* writing so we catch the live event.
  let resolveSeen!: (e: Event) => void
  const seen = new Promise<Event>((r) => (resolveSeen = r))
  const watch = { did: '', rkey: '' }
  const others: string[] = []
  const firehose = new Firehose({
    idResolver,
    service: relayUrl,
    filterCollections: [COLLECTION],
    handleEvent: async (evt) => {
      if (evt.event === 'identity' || evt.event === 'account') {
        others.push(`${evt.event}:${evt.did}`)
        return
      }
      if (evt.event === 'create' && evt.did === watch.did && evt.rkey === watch.rkey) resolveSeen(evt)
    },
    onError: (err) => console.error('[smoke] firehose error:', err.message),
  })
  void firehose.start()
  await new Promise((r) => setTimeout(r, 1000))
  step(`subscribed to ${relayUrl}`)

  // 2. Two accounts.
  const alice = await createAccount(`smk${run}a`)
  const bob = await createAccount(`smk${run}b`)
  step(`created ${alice.handle} = ${alice.did}`)
  step(`created ${bob.handle} = ${bob.did}`)

  // Sanity: PLC knows the DID and points it at this PDS.
  const doc = await idResolver.did.resolveAtprotoData(alice.did)
  step(`PLC: handle=${doc.handle} pds=${doc.pds}`)

  // 3. Write a message record from alice.
  const record = {
    $type: COLLECTION,
    tag: new Uint8Array(randomBytes(16)),
    envelopeType: 'whisper',
    ciphertext: new Uint8Array([1, 2, 3, 4, 5]),
    formatVersion: 1,
  }
  let put
  try {
    put = await alice.agent.com.atproto.repo.createRecord({ repo: alice.did, collection: COLLECTION, record })
    step('createRecord ok without validate flag')
  } catch (err) {
    step(`createRecord without validate flag failed (${(err as Error).message}); retrying with validate:false`)
    put = await alice.agent.com.atproto.repo.createRecord({ repo: alice.did, collection: COLLECTION, record, validate: false })
  }
  watch.did = alice.did
  watch.rkey = put.data.uri.split('/').pop()!
  step(`wrote ${put.data.uri} (validationStatus=${put.data.validationStatus ?? 'n/a'})`)

  const got = await alice.agent.com.atproto.repo.getRecord({ repo: alice.did, collection: COLLECTION, rkey: watch.rkey })
  const v = got.data.value as Record<string, unknown>
  if (!(v.tag instanceof Uint8Array) || v.tag.length !== 16) fail(`getRecord tag is not 16 bytes: ${JSON.stringify(v.tag)}`)
  step('getRecord round-trips bytes fields')

  // 4. Wait for the relay to deliver it.
  const timer = setTimeout(() => fail(`no firehose event for ${put.data.uri} within ${TIMEOUT_MS}ms`), TIMEOUT_MS)
  const evt = await seen
  clearTimeout(timer)
  if (evt.event !== 'create') fail('unexpected event type')
  const rec = (evt as Extract<Event, { event: 'create' }>).record as Record<string, unknown>
  const tagOk = rec.tag instanceof Uint8Array && Buffer.from(rec.tag).equals(Buffer.from(record.tag))
  if (!tagOk) fail('firehose record tag mismatch')
  step(`relay delivered seq=${evt.seq} ${evt.did}/${COLLECTION}/${watch.rkey} (signature verified, tag matches)`)
  if (others.length) step(`also saw: ${others.join(', ')}`)

  await firehose.destroy()

  console.log('\n=== recipe ===')
  console.log(`handle format : <3-18 chars [a-z0-9-]>.${HANDLE_DOMAIN}   e.g. ${alice.handle}`)
  console.log(`createAccount : POST ${pdsUrl}/xrpc/com.atproto.server.createAccount`)
  console.log(`  body        : ${JSON.stringify(alice.body)}`)
  console.log('  (no inviteCode; email required but never verified; record writes allowed immediately)')
  console.log('\nSMOKE OK')
  process.exit(0)
}

main().catch((err) => fail(err?.stack ?? String(err)))
