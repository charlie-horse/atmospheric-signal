// Builds the static did:web + lexicon-publishing site into ./site.
// The signing key is generated fresh on every run and never written anywhere.
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Secp256k1Keypair } from '@atproto/crypto'
import { Lexicons, type LexiconDoc } from '@atproto/lexicon'
import {
  MemoryBlockstore,
  Repo,
  WriteOpAction,
  concatBytesAsync,
  getFullRepo,
  type RecordCreateOp,
} from '@atproto/repo'

export const HOST = 'atsignal.neuros.is'
export const DID = `did:web:${HOST}`
export const SCHEMA_NSID = 'com.atproto.lexicon.schema'
export const GITHUB_URL = 'https://github.com/charlie-horse/atmospheric-signal'

const here = dirname(fileURLToPath(import.meta.url))
export const LEXICON_DIR = join(here, '../../lexicons/is/neuros/atsignal')
const SITE = join(here, 'site')

export async function loadLexicons(): Promise<LexiconDoc[]> {
  const files = (await readdir(LEXICON_DIR)).filter((f) => f.endsWith('.json')).sort()
  return Promise.all(files.map(async (f) => JSON.parse(await readFile(join(LEXICON_DIR, f), 'utf8'))))
}

async function main() {
  const docs = await loadLexicons()
  if (docs.length !== 7) throw new Error(`expected 7 lexicons, found ${docs.length}`)
  // Validates every doc (throws on a malformed one) and catches duplicate ids.
  // Lexicons rewrites refs in place (`#x` -> `lex:nsid#x`), so give it a copy.
  new Lexicons(structuredClone(docs))
  for (const d of docs) {
    if (!d.id.startsWith('is.neuros.atsignal.') || d.id.includes('#')) throw new Error(`bad id ${d.id}`)
  }

  const keypair = await Secp256k1Keypair.create({ exportable: true })
  const publicKeyMultibase = keypair.did().replace(/^did:key:/, '')

  // Record body is the lexicon doc itself; rkey must equal its `id`.
  const writes: RecordCreateOp[] = docs.map((doc) => ({
    action: WriteOpAction.Create,
    collection: SCHEMA_NSID,
    rkey: doc.id,
    record: { $type: SCHEMA_NSID, ...doc } as RecordCreateOp['record'],
  }))

  const storage = new MemoryBlockstore()
  const repo = await Repo.create(storage, DID, keypair, writes)
  const car = await concatBytesAsync(getFullRepo(storage, repo.cid))

  const records = []
  for (const doc of docs) {
    const cid = await repo.data.get(`${SCHEMA_NSID}/${doc.id}`)
    if (!cid) throw new Error(`record missing for ${doc.id}`)
    records.push({
      uri: `at://${DID}/${SCHEMA_NSID}/${doc.id}`,
      cid: cid.toString(),
      value: await repo.getRecord(SCHEMA_NSID, doc.id),
    })
  }

  const didDoc = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1',
      'https://w3id.org/security/suites/secp256k1-2019/v1',
    ],
    id: DID,
    alsoKnownAs: [`at://${HOST}`],
    verificationMethod: [
      { id: `${DID}#atproto`, type: 'Multikey', controller: DID, publicKeyMultibase },
    ],
    service: [
      { id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: `https://${HOST}` },
    ],
  }

  const json = (v: unknown) => JSON.stringify(v, null, 2) + '\n'
  const files: Record<string, string | Uint8Array> = {
    CNAME: `${HOST}\n`,
    '.nojekyll': '',
    '.well-known/did.json': json(didDoc),
    '.well-known/atproto-did': DID,
    'xrpc/com.atproto.sync.getRecord': car,
    'xrpc/com.atproto.sync.getRepo': car,
    'xrpc/com.atproto.sync.getLatestCommit': json({ cid: repo.cid.toString(), rev: repo.commit.rev }),
    'xrpc/com.atproto.repo.describeRepo': json({
      handle: HOST,
      did: DID,
      didDoc,
      collections: [SCHEMA_NSID],
      handleIsCorrect: true,
    }),
    'xrpc/com.atproto.repo.listRecords': json({ records }),
    'index.html':
      `<!doctype html><meta charset="utf-8"><title>${HOST}</title>` +
      `<p><code>${DID}</code> publishes the <code>is.neuros.atsignal.*</code> lexicons for ` +
      `<a href="${GITHUB_URL}">atmospheric-signal</a>.</p>\n`,
  }

  await rm(SITE, { recursive: true, force: true })
  for (const [rel, body] of Object.entries(files)) {
    const p = join(SITE, rel)
    await mkdir(dirname(p), { recursive: true })
    await writeFile(p, body)
  }

  console.log(`built ${SITE}`)
  console.log(`  did        ${DID}`)
  console.log(`  key        ${publicKeyMultibase}`)
  console.log(`  commit     ${repo.cid.toString()} rev ${repo.commit.rev}`)
  console.log(`  car        ${car.length} bytes, ${records.length} records`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main()
}
