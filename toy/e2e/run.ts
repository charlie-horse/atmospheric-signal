// End-to-end test against the local stack (toy/stack: PLC :2582, Tranquil PDS :3000, relay :2470).
// Starts its own AppView, registers three fresh accounts, and checks DMs, a group, removal with rekey,
// and that no public record names a recipient.
//
//   npx tsx run.ts            (stack must be up: ../stack/up.sh)

import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { AtsigClient, type InboxItem } from '../client/src/client.ts'
import { NSID, config, groupStateRkey, groupTag, currentWindow } from '../shared/src/index.ts'
// libsignal comes from the client package; e2e has no copy of its own.
import { ProtocolAddress, groupDecrypt } from '../client/node_modules/@signalapp/libsignal-client/dist/index.js'

const here = fileURLToPath(new URL('.', import.meta.url))
const handleDomain = process.env.ATSIG_HANDLE_DOMAIN ?? 'test'
const run = Date.now().toString(36)
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

function step(name: string) {
  console.log(`\n== ${name}`)
}

async function startAppview(): Promise<ChildProcess> {
  const data = mkdtempSync(join(tmpdir(), 'atsig-appview-'))
  const proc = spawn('npx', ['tsx', 'src/main.ts'], {
    cwd: join(here, '../appview'),
    env: { ...process.env, ATSIG_APPVIEW_DATA: data },
    stdio: ['ignore', 'inherit', 'inherit'],
  })
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${config.appviewUrl}/health`)
      if (res.ok) return proc
    } catch {}
    await sleep(500)
  }
  proc.kill()
  throw new Error('AppView did not become healthy')
}

/** Polls every inbox until a full round brings nothing new, then returns what each client received. */
async function settle(clients: AtsigClient[], quietRounds = 3): Promise<Map<AtsigClient, InboxItem[]>> {
  const got = new Map(clients.map((c) => [c, [] as InboxItem[]]))
  let quiet = 0
  for (let round = 0; round < 60 && quiet < quietRounds; round++) {
    let any = false
    for (const c of clients) {
      const items = await c.inbox()
      if (items.length) {
        any = true
        got.get(c)!.push(...items)
      }
    }
    quiet = any ? 0 : quiet + 1
    await sleep(1000)
  }
  return got
}

const texts = (items: InboxItem[] | undefined) =>
  (items ?? []).filter((i) => i.type === 'text').map((i) => (i as { text: string }).text)

async function main() {
  const appview = await startAppview()
  try {
    const home = mkdtempSync(join(tmpdir(), 'atsig-e2e-'))
    const mk = (name: string) =>
      new AtsigClient({ home, handle: `${name}-${run}.${handleDomain}`, password: `pw-${name}-${run}` })
    const alice = mk('alice')
    const bob = mk('bob')
    const carol = mk('carol')
    const all = [alice, bob, carol]

    step('register')
    for (const c of all) console.log(c.handle, (await c.register()).did)

    step('alice -> bob, first contact')
    await alice.send(bob.did, 'hi bob')
    let got = await settle(all)
    assert.deepEqual(texts(got.get(bob)), ['hi bob'])

    step('bob -> alice, reply on rotating tag')
    await bob.send(alice.did, 'hi alice')
    got = await settle(all)
    assert.deepEqual(texts(got.get(alice)), ['hi alice'])

    step('group: alice (admin), bob, carol')
    const gid = await alice.groupCreate('e2e', [bob.did, carol.did])
    await settle(all)
    await alice.groupSend(gid, 'group hello')
    await bob.groupSend(gid, 'bob in group')
    got = await settle(all)
    assert.deepEqual(texts(got.get(bob)), ['group hello'])
    assert.deepEqual(texts(got.get(carol)).sort(), ['bob in group', 'group hello'])
    assert.deepEqual(texts(got.get(alice)), ['bob in group'])

    step('alice removes carol; everyone rekeys')
    await alice.groupRemove(gid, carol.did)
    await settle(all)
    const window = currentWindow()
    await alice.groupSend(gid, 'after removal')
    await bob.groupSend(gid, 'bob after removal')
    got = await settle(all)
    assert.deepEqual(texts(got.get(bob)), ['after removal'])
    assert.deepEqual(texts(got.get(alice)), ['bob after removal'])
    assert.ok(!texts(got.get(carol)).some((t) => t.includes('after removal')), 'carol must not read post-removal messages')

    step('carol tries the post-removal ciphertexts directly')
    const page = await carol.transport.getMessagesByTag([groupTag(gid, window), groupTag(gid, window + 1)])
    const late = page.messages.filter((m) => m.envelopeType === 'senderKey').slice(-2)
    assert.equal(late.length, 2)
    for (const m of late) {
      await assert.rejects(
        groupDecrypt(ProtocolAddress.new(m.did, 1), carol.stores.senderKey, new Uint8Array(m.ciphertext)),
        `carol decrypted a post-removal message from ${m.did}`,
      )
    }
    console.log('both rejected')

    step('public records name no recipient')
    for (const sender of all) {
      const recs = await alice.transport.listRecords(sender.did, NSID.message)
      for (const { value } of recs) {
        const json = JSON.stringify(value)
        for (const other of all) {
          if (other !== sender) assert.ok(!json.includes(other.did), `${sender.handle} record names ${other.handle}`)
        }
      }
      console.log(`${sender.handle}: ${recs.length} message records, no recipient DIDs`)
    }
    assert.equal(await alice.transport.getRecord(alice.did, NSID.groupState, gid), null)
    assert.ok(await alice.transport.getRecord(alice.did, NSID.groupState, groupStateRkey(gid)))

    console.log('\nE2E PASS')
  } finally {
    appview.kill('SIGTERM')
  }
}

main().catch((err) => {
  console.error('\nE2E FAIL\n', err)
  process.exit(1)
})
