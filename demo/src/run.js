// Scenario: Alice and Bob talk over atsignal on one toy PDS, then we look at
// what a public observer can see. Run: npm run demo
import { Pds, TagIndexer } from './pds.js'
import { Client } from './client.js'
import { Groups } from './groups.js'
import { NS } from './lexicons.js'
import { WINDOW_MS } from './tags.js'

const h = (s) => console.log(`\n== ${s} ==`)
const log = (s) => console.log('  ' + s)
const hex = (b) => Buffer.from(b).toString('hex')
let t = Date.parse('2026-11-06T15:00:00Z')
const clock = { now: () => t }

const pds = new Pds()
const indexer = new TagIndexer(pds, `${NS}.message`)
const env = { pds, indexer, clock, log }
const alice = new Client('alice', 'did:plc:alice000000000000000000', env)
const bob = new Client('bob', 'did:plc:bob00000000000000000000', env)

h('1. Publish keys as repo records')
await alice.register()
await bob.register()

h('2. Alice starts a conversation (PQXDH from Bob\'s public records)')
await alice.startConversation(bob.did, 'hi bob, this is end-to-end encrypted')
await alice.sendText(bob.did, 'second message before you reply')
await bob.poll()

h('3. Bob replies over the rotating pairwise tag')
await bob.sendText(alice.did, 'hey alice, got both')
await alice.poll()
await alice.sendText(bob.did, 'now we are on the double ratchet')
await bob.poll()

h('4. An hour passes: tags rotate')
t += WINDOW_MS
await bob.sendText(alice.did, 'new hour, new tag')
await alice.poll()

h('5. Safety numbers (verify out of band)')
const a = alice.safetyNumber(bob.did), b = bob.safetyNumber(alice.did)
log(`alice sees: ${a}`)
log(`bob sees:   ${b}`)
log(a === b ? 'MATCH' : 'MISMATCH')

h('6. What a public observer sees (getRepo is unauthenticated)')
for (const c of [alice, bob]) {
  const msgs = pds.listRecords(c.did, `${NS}.message`)
  log(`${c.did}: ${msgs.length} message records`)
  for (const m of msgs) log(`  ${m.rkey}  tag=${hex(m.value.tag)}  type=${m.value.envelopeType.padEnd(12)} ${m.value.ciphertext.length}B`)
}
const aliceRepo = JSON.stringify(pds.getRepo(alice.did), (k, v) => (v instanceof Uint8Array ? hex(v) : v))
log(`Bob's DID in Alice's repo as plaintext: ${aliceRepo.includes(bob.did)}`)
log(`Bob's one-time prekeys left: ${pds.listRecords(bob.did, `${NS}.preKey`).length} of 3`)

h('7. Delete removes access, not copies (decision 5)')
const [first] = pds.listRecords(alice.did, `${NS}.message`)
pds.deleteRecord(alice.did, `${NS}.message`, first.rkey)
log(`PDS still serves it: ${pds.getRecord(alice.did, `${NS}.message`, first.rkey) !== null}`)
log(`Indexer still holds a copy: ${indexer.archive.has(`${alice.did}/${first.rkey}`)}`)

h('8. Groups: Alice creates {alice (admin), bob, carol}')
const carol = new Client('carol', 'did:plc:carol0000000000000000000', env)
const dave = new Client('dave', 'did:plc:dave00000000000000000000', env)
await carol.register()
await dave.register()
const users = [alice, bob, carol, dave]
for (const u of users) u.groups = new Groups(u)
// Deliver everything: poll all clients until nobody gets anything new.
async function sync() { for (let n = 1; n;) { n = 0; for (const u of users) n += await u.poll() } }
const G = (u) => u.groups.groups.get(gid)
const has = (u, text) => G(u).inbox.some((m) => m.text === text)
const checks = []
const check = (name, cond) => { checks.push([name, cond]); log(`${cond ? 'ok  ' : 'FAIL'} ${name}`) }
const gid = await alice.groups.create('weekend plans', [bob.did, carol.did])
await sync()

h('9. Each member sends one group message (one record each, envelopeType senderKey)')
for (const u of [alice, bob, carol]) await u.groups.sendText(gid, `hello group, ${u.name} here`)
await sync()
for (const u of [alice, bob, carol])
  check(`${u.name} read the other two`, [alice, bob, carol].filter((o) => o !== u).every((o) => has(u, `hello group, ${o.name} here`)))

h('10. Alice removes Carol; remaining members rekey')
await alice.groups.change(gid, [{ action: 'removeMember', did: carol.did }])
await sync()
const afterRemoval = await bob.groups.sendText(gid, 'carol is gone, new keys')
await sync()
check('alice read the post-removal message', has(alice, 'carol is gone, new keys'))
const carolTry = await carol.groups.tryDecrypt(afterRemoval)
log(`carol decrypting it from Bob's public repo: ${carolTry}`)
check('carol cannot decrypt the post-removal message', carolTry instanceof Error && !has(carol, 'carol is gone, new keys'))
check('carol sees herself removed', G(carol).removed)

h('11. Alice adds Dave; members rekey; no history for Dave')
const beforeJoin = await bob.groups.sendText(gid, 'secret plan before dave joins')
await sync()
await alice.groups.change(gid, [{ action: 'addMember', did: dave.did }])
await sync()
await alice.groups.sendText(gid, 'welcome dave')
await bob.groups.sendText(gid, 'hi dave')
await sync()
const daveTry = await dave.groups.tryDecrypt(beforeJoin)
log(`dave decrypting the pre-join message from Bob's public repo: ${daveTry}`)
check('dave cannot read the pre-join message', daveTry instanceof Error && !has(dave, 'secret plan before dave joins'))
check('dave reads post-join messages', has(dave, 'welcome dave') && has(dave, 'hi dave'))
await dave.groups.sendText(gid, 'thanks, dave here')
await sync()
check('alice and bob read dave', has(alice, 'thanks, dave here') && has(bob, 'thanks, dave here'))
check('carol got nothing after removal', G(carol).inbox.length === 2)

h('12. Bob (not an admin) forges groupChanges')
const ep = G(alice).epoch
const forged = [
  bob.groups.signChange(gid, ep + 1, [{ action: 'removeMember', did: alice.did }]), // signed by Bob as Bob
  bob.groups.signChange(gid, ep + 1, [{ action: 'addAdmin', did: bob.did }], alice.did), // claims Alice, Bob's key
]
for (const f of forged) for (const to of [alice.did, dave.did]) await bob.send(to, f)
await sync()
check('forged changes rejected, epoch unchanged',
  [alice, dave].every((u) => G(u).epoch === ep && G(u).rejected.length === 2) && G(alice).members.includes(alice.did))

h('13. What a public observer sees of the group')
const gs = pds.getRecord(alice.did, `${NS}.groupState`, gid)
log(`groupState ${gid} in alice's repo: epoch=${gs.epoch} (public), ${gs.stateCiphertext.length}B ciphertext`)
for (const u of users) {
  const recs = pds.listRecords(u.did, `${NS}.message`).map((m) => m.value.envelopeType)
  const n = (t) => recs.filter((x) => x === t).length
  log(`${u.name.padEnd(5)} repo: ${n('senderKey')} senderKey, ${n('firstContact')} firstContact, ${n('prekey') + n('whisper')} pairwise`)
}
const anyRepo = JSON.stringify(users.map((u) => pds.getRepo(u.did)), (k, v) => (v instanceof Uint8Array ? hex(v) : v))
check('no member DID or group title in any public record', ![carol.did, dave.did].some((d) => anyRepo.includes(d)) && !anyRepo.includes('weekend'))

h('Result')
const pairOk = bob.inbox.length === 3 && alice.inbox.length === 2 && a === b
log(`pairwise: bob got ${bob.inbox.length}/3, alice got ${alice.inbox.length}/2  ->  ${pairOk ? 'PASS' : 'FAIL'}`)
const groupOk = checks.every(([, c]) => c)
log(`groups: ${checks.filter(([, c]) => c).length}/${checks.length} checks  ->  ${groupOk ? 'PASS' : 'FAIL'}`)
const ok = pairOk && groupOk
log(ok ? 'PASS' : 'FAIL')
process.exit(ok ? 0 : 1)
