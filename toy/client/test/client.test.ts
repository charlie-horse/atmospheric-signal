import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  CiphertextMessageType,
  IdentityKeyPair,
  KEMKeyPair,
  KyberPreKeyRecord,
  PreKeyBundle,
  PreKeyRecord,
  PreKeySignalMessage,
  PrivateKey,
  ProtocolAddress,
  SignalMessage,
  SignedPreKeyRecord,
  groupDecrypt,
  processPreKeyBundle,
  signalDecrypt,
  signalDecryptPreKey,
  signalEncrypt,
} from '@signalapp/libsignal-client'
import { NSID, tagToParam, groupTag, groupStateRkey, currentWindow } from '../../shared/src/index.ts'
import { AtsigClient, type InboxItem } from '../src/client.ts'
import { SignalStores, StateFile, b64 } from '../src/state.ts'
import { MemoryNetwork } from '../src/transport.ts'

const home = () => mkdtempSync(join(tmpdir(), 'atsig-test-'))
const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

test('store layer: PreKeyBundle -> first message -> reply', async () => {
  const mk = (did: string) => {
    const file = new StateFile(home(), did.replace(/:/g, '_'))
    const id = IdentityKeyPair.generate()
    file.state.did = did
    file.state.identityKeyPair = b64(id.serialize())
    file.state.registrationId = 42
    return { file, stores: new SignalStores(() => file.state), id, addr: ProtocolAddress.new(did, 1) }
  }
  const alice = mk('did:plc:alice')
  const bob = mk('did:plc:bob')

  // Bob's keys.
  const spkPriv = PrivateKey.generate()
  const spk = SignedPreKeyRecord.new(1, Date.now(), spkPriv.getPublicKey(), spkPriv, bob.id.privateKey.sign(spkPriv.getPublicKey().serialize()))
  await bob.stores.signedPreKey.saveSignedPreKey(1, spk)
  const kem = KEMKeyPair.generate()
  const kpk = KyberPreKeyRecord.new(1, Date.now(), kem, bob.id.privateKey.sign(kem.getPublicKey().serialize()))
  await bob.stores.kyberPreKey.saveKyberPreKey(1, kpk)
  const pkPriv = PrivateKey.generate()
  await bob.stores.preKey.savePreKey(7, PreKeyRecord.new(7, pkPriv.getPublicKey(), pkPriv))

  const bundle = PreKeyBundle.new(42, 1, 7, pkPriv.getPublicKey(), 1, spk.publicKey(), spk.signature(), bob.id.publicKey, 1, kem.getPublicKey(), kpk.signature())
  await processPreKeyBundle(bundle, bob.addr, alice.addr, alice.stores.session, alice.stores.identity)

  const first = await signalEncrypt(enc('hello bob'), bob.addr, alice.addr, alice.stores.session, alice.stores.identity)
  assert.equal(first.type(), CiphertextMessageType.PreKey)
  const pt = await signalDecryptPreKey(
    PreKeySignalMessage.deserialize(first.serialize()),
    alice.addr, bob.addr, bob.stores.session, bob.stores.identity, bob.stores.preKey, bob.stores.signedPreKey, bob.stores.kyberPreKey,
  )
  assert.equal(dec(pt), 'hello bob')
  assert.equal(bob.file.state.preKeys['7'], undefined, 'one-time prekey consumed')

  // Persist and reload Bob's state to prove the JSON round trip.
  bob.file.save()
  const bob2 = new StateFile(join(bob.file.path, '..'), 'did_plc_bob')
  const bobStores2 = new SignalStores(() => bob2.state)

  const reply = await signalEncrypt(enc('hi alice'), alice.addr, bob.addr, bobStores2.session, bobStores2.identity)
  assert.equal(reply.type(), CiphertextMessageType.Whisper)
  const pt2 = await signalDecrypt(SignalMessage.deserialize(reply.serialize()), bob.addr, alice.addr, alice.stores.session, alice.stores.identity)
  assert.equal(dec(pt2), 'hi alice')

  const third = await signalEncrypt(enc('third'), bob.addr, alice.addr, alice.stores.session, alice.stores.identity)
  assert.equal(third.type(), CiphertextMessageType.Whisper)
})

function network() {
  const net = new MemoryNetwork()
  const client = (name: string) =>
    new AtsigClient({ home: home(), handle: `${name}.test`, password: `pw-${name}`, transport: net.transport() })
  return { net, client }
}

/** Runs inbox on every client until the network goes quiet. Returns everything each one received. */
async function settle(net: MemoryNetwork, clients: AtsigClient[]): Promise<Map<AtsigClient, InboxItem[]>> {
  const got = new Map<AtsigClient, InboxItem[]>(clients.map((c) => [c, []]))
  for (let round = 0; round < 10; round++) {
    const before = net.index.length
    for (const c of clients) got.get(c)!.push(...(await c.inbox()))
    if (net.index.length === before) return got
  }
  throw new Error('network did not settle')
}

const texts = (items: InboxItem[]) => items.flatMap((i) => (i.type === 'text' ? [i.text] : []))
const errors = (items: InboxItem[]) => items.filter((i) => i.type === 'error')

test('client: register, first contact, reply, prekey record deleted', async () => {
  const { net, client } = network()
  const alice = client('alice')
  const bob = client('bob')
  await alice.register()
  const { did: bobDid } = await bob.register()
  assert.equal((await alice.transport.listRecords(bobDid, NSID.preKey)).length, 10)
  assert.equal((await alice.transport.listRecords(bobDid, NSID.device)).length, 1)

  await alice.send('bob.test', 'hello bob')
  await alice.send(bobDid, 'second')
  const b1 = await bob.inbox()
  assert.deepEqual(errors(b1), [])
  assert.deepEqual(texts(b1), ['hello bob', 'second'])
  assert.ok(b1.every((i) => i.type !== 'text' || i.from === alice.did))
  assert.equal((await alice.transport.listRecords(bobDid, NSID.preKey)).length, 9, 'consumed prekey record deleted')
  assert.deepEqual(await bob.inbox(), [], 'nothing new on second poll')

  await bob.send(alice.did, 'hi alice')
  const a1 = await alice.inbox()
  assert.deepEqual(texts(a1), ['hi alice'])

  await alice.send('bob.test', 'third')
  assert.deepEqual(texts(await bob.inbox()), ['third'])
  // The envelope types on the wire: firstContact, prekey, prekey, whisper (bob), whisper.
  assert.deepEqual(net.index.map((e) => e.view.envelopeType), ['firstContact', 'prekey', 'prekey', 'whisper', 'whisper'])

  // State survives a reload from disk.
  const bob2 = new AtsigClient({ home: join(bob.file.path, '..'), handle: 'bob.test', password: 'pw-bob', transport: net.transport() })
  await alice.send('bob.test', 'after reload')
  assert.deepEqual(texts(await bob2.inbox()), ['after reload'])
})

test('client: two senders racing for the same one-time prekey both get through', async () => {
  const { net, client } = network()
  const [alice, carol, bob] = ['alice', 'carol', 'bob'].map(client) as [AtsigClient, AtsigClient, AtsigClient]
  for (const x of [alice, carol, bob]) await x.register()
  const coll = net.repo(bob.did).get(NSID.preKey)!
  for (const rkey of [...coll.keys()].slice(1)) coll.delete(rkey)
  await alice.send(bob.did, 'from alice')
  await carol.send(bob.did, 'from carol')
  const got = await bob.inbox()
  assert.deepEqual(errors(got), [])
  assert.deepEqual(texts(got).sort(), ['from alice', 'from carol'])
  assert.equal((await alice.transport.listRecords(bob.did, NSID.preKey)).length, 0, 'the shared prekey record is deleted')
})

test('client: 3-member sender-key group, removal rotates keys, add gets no history', async () => {
  const { net, client } = network()
  const [a, b, c, d] = ['ann', 'ben', 'cat', 'dan'].map(client) as [AtsigClient, AtsigClient, AtsigClient, AtsigClient]
  for (const x of [a, b, c, d]) await x.register()

  const gid = await a.groupCreate('toy group', [b.did, 'cat.test'])
  assert.match(gid, /^[0-9A-Za-z]{22}$/)
  assert.ok(await a.transport.getRecord(a.did, NSID.groupState, groupStateRkey(gid)))
  assert.equal(await a.transport.getRecord(a.did, NSID.groupState, gid), null, 'groupId must not be the public rkey')
  let got = await settle(net, [a, b, c])
  for (const x of [b, c]) {
    assert.deepEqual(errors(got.get(x)!), [])
    assert.ok(got.get(x)!.some((i) => i.type === 'group' && i.event === 'joined' && i.groupId === gid))
    assert.deepEqual(x.groups()[0]!.members.sort(), [a.did, b.did, c.did].sort())
  }

  await a.groupSend(gid, 'hello group')
  await b.groupSend(gid, 'ben here')
  got = await settle(net, [a, b, c])
  assert.deepEqual(texts(got.get(b)!), ['hello group'])
  assert.deepEqual(texts(got.get(c)!), ['hello group', 'ben here'])
  assert.deepEqual(texts(got.get(a)!), ['ben here'])
  assert.ok(got.get(c)!.every((i) => i.type !== 'text' || i.groupId === gid))

  // Remove cat. Every remaining member rotates.
  const distA = a.state.groups[gid]!.myDistributionId
  const distB = b.state.groups[gid]!.myDistributionId
  await a.groupRemove(gid, c.did)
  got = await settle(net, [a, b, c])
  assert.ok(got.get(c)!.some((i) => i.type === 'group' && i.event === 'removed'))
  assert.ok(got.get(b)!.some((i) => i.type === 'group' && i.event === 'change'))
  assert.equal(c.state.groups[gid]!.left, true)
  assert.notEqual(a.state.groups[gid]!.myDistributionId, distA)
  assert.notEqual(b.state.groups[gid]!.myDistributionId, distB)
  assert.equal(b.state.groups[gid]!.epoch, 1)

  await a.groupSend(gid, 'after removal')
  const raw = net.index[net.index.length - 1]!.view
  assert.equal(raw.envelopeType, 'senderKey')
  assert.equal(tagToParam(raw.tag), tagToParam(groupTag(gid, currentWindow())))
  // The removed member still holds the old sender keys, but not the rotated one.
  await assert.rejects(groupDecrypt(ProtocolAddress.new(a.did, 1), c.stores.senderKey, new Uint8Array(raw.ciphertext)))
  await b.groupSend(gid, 'ben after removal')
  const rawB = net.index[net.index.length - 1]!.view
  await assert.rejects(groupDecrypt(ProtocolAddress.new(b.did, 1), c.stores.senderKey, new Uint8Array(rawB.ciphertext)))

  got = await settle(net, [a, b, c])
  assert.deepEqual(texts(got.get(b)!), ['after removal'])
  assert.deepEqual(texts(got.get(a)!), ['ben after removal'])
  assert.deepEqual(got.get(c)!, [])

  // A removed member's group messages are no longer accepted.
  c.state.groups[gid]!.left = false
  await c.groupSend(gid, 'ghost')
  got = await settle(net, [a, b])
  assert.deepEqual(texts(got.get(a)!), [])
  assert.ok(errors(got.get(a)!).length === 1)

  // Add dan: no history, but everything after the join.
  await a.groupAdd(gid, d.did)
  got = await settle(net, [a, b, d])
  assert.ok(got.get(d)!.some((i) => i.type === 'group' && i.event === 'joined'))
  assert.deepEqual(texts(got.get(d)!), [], 'no history for the joiner')
  assert.deepEqual(errors(got.get(d)!), [])
  await b.groupSend(gid, 'welcome dan')
  await d.groupSend(gid, 'thanks')
  got = await settle(net, [a, b, d])
  assert.deepEqual(texts(got.get(d)!), ['welcome dan'])
  assert.deepEqual(texts(got.get(a)!), ['welcome dan', 'thanks'])
  assert.deepEqual(texts(got.get(b)!), ['thanks'])
  assert.equal(d.state.groups[gid]!.epoch, 2)
})

test('client: forged group change is rejected', async () => {
  const { net, client } = network()
  const [a, b, c] = ['amy', 'bob', 'cyd'].map(client) as [AtsigClient, AtsigClient, AtsigClient]
  for (const x of [a, b, c]) await x.register()
  const gid = await a.groupCreate('g', [b.did, c.did])
  await settle(net, [a, b, c])
  // b is not an admin; pretend it is locally so it can sign and send a change.
  b.state.groups[gid]!.admins.push(b.did)
  await b.groupRemove(gid, c.did)
  const got = await settle(net, [a, c])
  assert.ok(errors(got.get(a)!).some((i) => i.type === 'error' && /not an admin/.test(i.error)))
  assert.equal(a.state.groups[gid]!.epoch, 0)
  assert.equal(c.state.groups[gid]!.left, undefined)
})
