import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import * as dagCbor from '@ipld/dag-cbor'
import {
  NSID,
  FORMAT_VERSION,
  config,
  loadLexiconDocs,
  lexicons,
  TAG_WINDOW_MS,
  currentWindow,
  pairTag,
  firstContactTag,
  groupTag,
  tagToParam,
  tagFromParam,
  encodePlaintext,
  decodePlaintext,
  groupChangeSigningBytes,
  sealGroupState,
  openGroupState,
  resolveDid,
  resolveHandle,
  type Content,
  type GroupChange,
  type GroupSnapshot,
} from '../src/index.ts'

const alice = 'did:plc:aliceaaaaaaaaaaaaaaaaaaa'
const bob = 'did:plc:bobbbbbbbbbbbbbbbbbbbbbb'
const seed = new Uint8Array(32).fill(7)
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

test('ids and lexicons', () => {
  assert.equal(FORMAT_VERSION, 1)
  const docs = loadLexiconDocs()
  assert.equal(docs.length, 7)
  for (const id of Object.values(NSID)) {
    assert.ok(docs.some((d) => d.id === id), id)
    assert.ok(lexicons.get(id), id)
  }
  const rec = { tag: new Uint8Array(16), envelopeType: 'whisper', ciphertext: new Uint8Array([1]), formatVersion: 1 }
  assert.doesNotThrow(() => lexicons.assertValidRecord(NSID.message, { $type: NSID.message, ...rec }))
})

test('currentWindow', () => {
  assert.equal(currentWindow(0), 0)
  assert.equal(currentWindow(TAG_WINDOW_MS - 1), 0)
  assert.equal(currentWindow(TAG_WINDOW_MS * 5 + 1), 5)
  assert.equal(currentWindow(), Math.floor(Date.now() / TAG_WINDOW_MS))
})

test('tags are 16 bytes, deterministic, and directional', () => {
  const w = 123456
  const ab = pairTag(seed, alice, bob, w)
  assert.equal(ab.length, 16)
  assert.deepEqual(ab, pairTag(seed, alice, bob, w))
  assert.notEqual(hex(ab), hex(pairTag(seed, bob, alice, w)))
  assert.notEqual(hex(ab), hex(pairTag(seed, alice, bob, w + 1)))
  assert.notEqual(hex(ab), hex(pairTag(new Uint8Array(32).fill(8), alice, bob, w)))

  const fc = firstContactTag(bob)
  assert.equal(fc.length, 16)
  assert.deepEqual(fc, firstContactTag(bob))
  assert.notEqual(hex(fc), hex(firstContactTag(alice)))

  const g = groupTag('group-1', w)
  assert.equal(g.length, 16)
  assert.deepEqual(g, groupTag('group-1', w))
  assert.notEqual(hex(g), hex(groupTag('group-1', w + 1)))
  assert.notEqual(hex(g), hex(groupTag('group-2', w)))
})

test('tag algorithms match the contract', async () => {
  const { createHash, createHmac } = await import('node:crypto')
  const w = 42
  const want = createHmac('sha256', seed).update(`atsignal-pair\0${alice}\0${bob}\0${w}`).digest().subarray(0, 16)
  assert.equal(hex(pairTag(seed, alice, bob, w)), want.toString('hex'))
  const fc = createHash('sha256').update(`atsignal-first-contact\0${bob}`).digest().subarray(0, 16)
  assert.equal(hex(firstContactTag(bob)), fc.toString('hex'))
  const g = createHmac('sha256', 'gid').update(`atsignal-group\0${w}`).digest().subarray(0, 16)
  assert.equal(hex(groupTag('gid', w)), g.toString('hex'))
})

test('base64url round trip', () => {
  for (let n = 0; n < 40; n++) {
    const bytes = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff)
    const s = tagToParam(bytes)
    assert.match(s, /^[A-Za-z0-9_-]*$/)
    assert.ok(!s.includes('='))
    assert.deepEqual(tagFromParam(s), bytes)
  }
  const tag = pairTag(seed, alice, bob, 1)
  assert.equal(tagToParam(tag).length, 22)
  assert.deepEqual(tagFromParam(tagToParam(tag)), tag)
  // subarray views encode only their own bytes
  const big = new Uint8Array([9, 9, 1, 2, 3, 9])
  assert.equal(tagToParam(big.subarray(2, 5)), tagToParam(new Uint8Array([1, 2, 3])))
  assert.throws(() => tagFromParam('abc+'))
  assert.throws(() => tagFromParam('ab=='))
})

const groupChange: GroupChange = {
  $type: 'is.neuros.atsignal.defs#groupChange',
  groupId: 'g1',
  epoch: 2,
  actions: [
    { action: 'addMember', did: bob },
    { action: 'addAdmin', did: bob },
  ],
  signerDid: alice,
  signature: new Uint8Array(64).fill(3),
}
const snapshot: GroupSnapshot = {
  $type: 'is.neuros.atsignal.defs#groupSnapshot',
  groupId: 'g1',
  epoch: 1,
  members: [alice, bob],
  admins: [alice],
  title: 'Friends',
}

test('plaintext round trip for all content types', () => {
  const contents: Content[] = [
    { $type: 'is.neuros.atsignal.defs#text', text: 'hello 👋' },
    { $type: 'is.neuros.atsignal.defs#conversationInit', tagSeed: seed },
    { $type: 'is.neuros.atsignal.defs#senderKeyDistribution', groupId: 'g1', distributionMessage: new Uint8Array([1, 2, 3]) },
    groupChange,
    snapshot,
    { ...snapshot, title: undefined },
  ]
  for (const c of contents) {
    const bytes = encodePlaintext(c)
    assert.ok(bytes instanceof Uint8Array)
    const back = decodePlaintext(bytes)
    const expected = Object.fromEntries(Object.entries(c).filter(([, v]) => v !== undefined))
    assert.deepEqual({ ...back }, expected)
    assert.deepEqual(dagCbor.decode(bytes), { content: expected })
  }
})

test('invalid plaintext is rejected', () => {
  const bad = (c: unknown) => encodePlaintext(c as Content)
  assert.throws(() => bad({ $type: 'is.neuros.atsignal.defs#conversationInit', tagSeed: new Uint8Array(31) }))
  assert.throws(() => bad({ $type: 'is.neuros.atsignal.defs#conversationInit', tagSeed: 'not bytes' }))
  assert.throws(() => bad({ $type: 'is.neuros.atsignal.defs#text' }))
  assert.throws(() => bad({ $type: 'is.neuros.atsignal.defs#nope', text: 'x' }))
  assert.throws(() => bad({ ...groupChange, actions: [] }))
  assert.throws(() => bad({ ...groupChange, signerDid: 'alice' }))
  assert.throws(() => bad({ ...snapshot, admins: [] }))
  // decode side: valid CBOR, invalid content
  const raw = dagCbor.encode({ content: { $type: 'is.neuros.atsignal.defs#conversationInit', tagSeed: new Uint8Array(31) } })
  assert.throws(() => decodePlaintext(raw))
  assert.throws(() => decodePlaintext(dagCbor.encode({ nope: 1 })))
  assert.throws(() => decodePlaintext(new Uint8Array([0xff, 0x00])))
})

test('groupChangeSigningBytes is deterministic and excludes signature', () => {
  const { signature, ...unsigned } = groupChange
  const a = groupChangeSigningBytes(unsigned)
  // key order does not matter
  const reordered = { signerDid: unsigned.signerDid, actions: unsigned.actions, epoch: 2, groupId: 'g1', $type: unsigned.$type }
  assert.deepEqual(groupChangeSigningBytes(reordered), a)
  // a signature passed at runtime is ignored
  assert.deepEqual(groupChangeSigningBytes(groupChange), a)
  const withSig: Omit<GroupChange, 'signature'> = { ...groupChange, signature: new Uint8Array([9]) } as GroupChange
  assert.deepEqual(groupChangeSigningBytes(withSig), a)
  const decoded = dagCbor.decode(a) as Record<string, unknown>
  assert.ok(!('signature' in decoded))
  assert.deepEqual(decoded, unsigned)
  assert.ok(signature.length > 0)
  // changing any field changes the bytes
  assert.notDeepEqual(groupChangeSigningBytes({ ...unsigned, epoch: 3 }), a)
  assert.throws(() => groupChangeSigningBytes({ ...unsigned, actions: [] }))
})

test('sealGroupState / openGroupState round trip and tamper detection', () => {
  const sealed = sealGroupState('g1', snapshot)
  assert.deepEqual({ ...openGroupState('g1', sealed) }, snapshot)
  // random nonce: two seals differ
  assert.notDeepEqual(sealGroupState('g1', snapshot), sealed)

  for (const i of [0, 12, sealed.length - 1]) {
    const t = new Uint8Array(sealed)
    t[i]! ^= 1
    assert.throws(() => openGroupState('g1', t), `tamper at ${i}`)
  }
  assert.throws(() => openGroupState('g2', sealed))
  assert.throws(() => openGroupState('g1', sealed.subarray(0, 20)))
  assert.throws(() => sealGroupState('g2', snapshot)) // groupId mismatch
  assert.throws(() => sealGroupState('g1', { ...snapshot, admins: [] }))
})

test('resolveDid and resolveHandle against a fake PLC/PDS', async () => {
  const doc = {
    id: alice,
    alsoKnownAs: ['at://alice.test'],
    verificationMethod: [{ id: `${alice}#atproto`, type: 'Multikey', controller: alice, publicKeyMultibase: 'zQ3shKEY' }],
    service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://localhost:3000' }],
  }
  const server = createServer((req, res) => {
    const u = new URL(req.url!, 'http://x')
    res.setHeader('content-type', 'application/json')
    if (u.pathname === `/${alice}`) return res.end(JSON.stringify(doc))
    if (u.pathname === '/xrpc/com.atproto.identity.resolveHandle' && u.searchParams.get('handle') === 'alice.test') {
      return res.end(JSON.stringify({ did: alice }))
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'NotFound' }))
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const base = `http://localhost:${(server.address() as AddressInfo).port}`
  const saved = { ...config }
  try {
    config.plcUrl = base
    config.pdsUrl = base
    const r = await resolveDid(alice)
    assert.deepEqual(r, { did: alice, handle: 'alice.test', pdsUrl: base, signingKey: 'zQ3shKEY' })
    assert.equal(await resolveHandle('@alice.test'), alice)
    await assert.rejects(resolveHandle('nobody.test'))
    await assert.rejects(resolveDid(bob))
    await assert.rejects(resolveDid('did:key:z123'))
    // non-matching host: endpoint returned as-is
    config.pdsUrl = 'http://pds.example:3000'
    assert.equal((await resolveDid(alice)).pdsUrl, 'https://localhost:3000')
  } finally {
    Object.assign(config, saved)
    server.close()
  }
})
