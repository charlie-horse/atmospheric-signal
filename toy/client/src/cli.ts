#!/usr/bin/env -S npx tsx
// atsig: thin CLI over AtsigClient. Prints JSON results on stdout.

import { parseArgs } from 'node:util'
import { AtsigClient } from './client.ts'

const USAGE = `usage: atsig --home DIR --handle H --password P [--email E] <command>

commands:
  register                     create the account (or log in) and publish keys
  whoami                       show handle, DID, identity key, contacts, groups
  send <to> <text>             send a text to a handle or DID
  inbox                        fetch, decrypt and print new messages
  group create <title> <dids...>
  group send <id> <text>
  group add <id> <did>
  group remove <id> <did>
  group list

Options fall back to ATSIG_HOME, ATSIG_HANDLE, ATSIG_PASSWORD, ATSIG_EMAIL.`

function fail(msg: string): never {
  process.stderr.write(`${msg}\n`)
  process.exit(2)
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      home: { type: 'string' },
      handle: { type: 'string' },
      password: { type: 'string' },
      email: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  })
  if (values.help || positionals.length === 0) {
    console.log(USAGE)
    return
  }
  const home = values.home ?? process.env.ATSIG_HOME
  const handle = values.handle ?? process.env.ATSIG_HANDLE
  const password = values.password ?? process.env.ATSIG_PASSWORD
  const email = values.email ?? process.env.ATSIG_EMAIL
  if (!home || !handle || !password) fail(`--home, --handle and --password are required\n\n${USAGE}`)

  const client = new AtsigClient({ home, handle, password, email })
  const [cmd, ...rest] = positionals
  const need = (n: number, what: string): void => {
    if (rest.length < n) fail(`usage: atsig ${what}`)
  }

  let result: unknown
  switch (cmd) {
    case 'register':
      result = await client.register()
      break
    case 'whoami':
      result = client.whoami()
      break
    case 'send':
      need(2, 'send <to> <text>')
      result = await client.send(rest[0]!, rest.slice(1).join(' '))
      break
    case 'inbox':
      result = await client.inbox()
      break
    case 'group': {
      const [sub, ...args] = rest
      switch (sub) {
        case 'create':
          if (args.length < 2) fail('usage: atsig group create <title> <dids...>')
          result = { groupId: await client.groupCreate(args[0]!, args.slice(1)) }
          break
        case 'send':
          if (args.length < 2) fail('usage: atsig group send <id> <text>')
          result = await client.groupSend(args[0]!, args.slice(1).join(' '))
          break
        case 'add':
          if (args.length !== 2) fail('usage: atsig group add <id> <did>')
          result = await client.groupAdd(args[0]!, args[1]!)
          break
        case 'remove':
          if (args.length !== 2) fail('usage: atsig group remove <id> <did>')
          result = await client.groupRemove(args[0]!, args[1]!)
          break
        case 'list':
          result = client.groups()
          break
        default:
          fail(`unknown group command ${sub ?? ''}\n\n${USAGE}`)
      }
      break
    }
    default:
      fail(`unknown command ${cmd}\n\n${USAGE}`)
  }
  console.log(JSON.stringify(result, null, 2))
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? (process.env.ATSIG_DEBUG ? (e.stack ?? e.message) : e.message) : String(e)
  process.stderr.write(`atsig: ${msg}\n`)
  process.exit(1)
})
