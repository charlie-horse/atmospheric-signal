# Toy contract

Shared interfaces for the toy packages. Every package codes against this file.

## Layout

Each directory is an independent npm package (`"type": "module"`, own `package.json`, own `node_modules`, own `tsconfig.json` extending `../tsconfig.base.json`). Packages run with `tsx`. They import each other by relative path to the TypeScript source, e.g. `import { pairTag } from '../../shared/src/index.ts'`. There are no npm workspaces.

| Dir | Owner | Purpose |
|---|---|---|
| `toy/shared` | Grace Hopper | Lexicons, tags, plaintext codec, identity resolution, config |
| `toy/stack` | Linus Torvalds | Local PLC + Tranquil PDS + indigo relay |
| `toy/appview` | Barbara Liskov | Firehose indexer + `getMessagesByTag` |
| `toy/client` | Alan Turing | `AtsigClient` class + `atsig` CLI |
| `toy/publish` | Tim Berners-Lee | did:web site + lexicon publishing |
| `toy/e2e` | main session | End-to-end test |

Lexicon JSON lives in `lexicons/is/neuros/atsignal/` at the repo root (7 files, including `getMessagesByTag.json`). Don't edit them without telling the main session.

## Local endpoints (`toy/shared/src/config.ts`)

```ts
export const config = {
  plcUrl:     process.env.ATSIG_PLC_URL     ?? 'http://localhost:2582',
  pdsUrl:     process.env.ATSIG_PDS_URL     ?? 'http://localhost:3000',
  relayUrl:   process.env.ATSIG_RELAY_URL   ?? 'ws://localhost:2470',
  appviewUrl: process.env.ATSIG_APPVIEW_URL ?? 'http://localhost:4000',
}
```

## `toy/shared/src/index.ts` exports

```ts
// ids
export const NSID: {
  identity: 'is.neuros.atsignal.identity'; device: 'is.neuros.atsignal.device';
  preKey: 'is.neuros.atsignal.preKey'; message: 'is.neuros.atsignal.message';
  groupState: 'is.neuros.atsignal.groupState'; defs: 'is.neuros.atsignal.defs';
  getMessagesByTag: 'is.neuros.atsignal.getMessagesByTag';
}
export const FORMAT_VERSION = 1
export { config }

// lexicons
export function loadLexiconDocs(): LexiconDoc[]          // the 7 JSON files
export const lexicons: Lexicons                          // @atproto/lexicon instance with all 7 loaded

// tags (all return 16-byte Uint8Array)
export const TAG_WINDOW_MS = 3_600_000
export function currentWindow(nowMs?: number): number    // Math.floor(now / TAG_WINDOW_MS)
export function pairTag(tagSeed: Uint8Array, fromDid: string, toDid: string, window: number): Uint8Array
//   HMAC-SHA256(key = tagSeed, msg = utf8("atsignal-pair\0" + fromDid + "\0" + toDid + "\0" + window)).slice(0, 16)
export function firstContactTag(recipientDid: string): Uint8Array
//   SHA-256(utf8("atsignal-first-contact\0" + recipientDid)).slice(0, 16)
export function groupTag(groupId: string, window: number): Uint8Array
//   HMAC-SHA256(key = utf8(groupId), msg = utf8("atsignal-group\0" + window)).slice(0, 16)
export function tagToParam(tag: Uint8Array): string      // base64url, no padding
export function tagFromParam(s: string): Uint8Array

// plaintext (inside ciphertext): DAG-CBOR of { content: Content }, validated against defs#plaintext
export type Text = { $type: 'is.neuros.atsignal.defs#text'; text: string }
export type ConversationInit = { $type: 'is.neuros.atsignal.defs#conversationInit'; tagSeed: Uint8Array }
export type SenderKeyDistribution = { $type: 'is.neuros.atsignal.defs#senderKeyDistribution'; groupId: string; distributionMessage: Uint8Array }
export type GroupAction = { action: 'addMember' | 'removeMember' | 'addAdmin' | 'removeAdmin' | (string & {}); did: string }
export type GroupChange = { $type: 'is.neuros.atsignal.defs#groupChange'; groupId: string; epoch: number; actions: GroupAction[]; signerDid: string; signature: Uint8Array }
export type GroupSnapshot = { $type: 'is.neuros.atsignal.defs#groupSnapshot'; groupId: string; epoch: number; members: string[]; admins: string[]; title?: string }
export type Content = Text | ConversationInit | SenderKeyDistribution | GroupChange | GroupSnapshot
export function encodePlaintext(content: Content): Uint8Array   // validates, then DAG-CBOR
export function decodePlaintext(bytes: Uint8Array): Content     // DAG-CBOR, then validates
export function groupChangeSigningBytes(change: Omit<GroupChange, 'signature'>): Uint8Array  // DAG-CBOR of the change without `signature`

// group state record encryption (toy: key = HKDF-SHA256(utf8(groupId), info "atsignal-group-state"), AES-256-GCM, 12-byte nonce prefixed)
export function sealGroupState(groupId: string, snapshot: GroupSnapshot): Uint8Array
export function openGroupState(groupId: string, sealed: Uint8Array): GroupSnapshot

// identity
export async function resolveDid(did: string): Promise<{ did: string; handle?: string; pdsUrl: string; signingKey?: string }>  // did:plc via config.plcUrl, did:web via https
export async function resolveHandle(handle: string): Promise<string>  // com.atproto.identity.resolveHandle on config.pdsUrl
```

## Record shapes written by the client

- `is.neuros.atsignal.identity` / rkey `self`: `{ identityKey: PublicKey.serialize() (33 bytes), formatVersion: 1, createdAt }`
- `is.neuros.atsignal.device` / rkey random: `{ deviceId: 1, registrationId, signedPreKey: {keyId, publicKey, signature}, kyberPreKey: {keyId, publicKey, signature}, formatVersion: 1, createdAt }`
- `is.neuros.atsignal.preKey` / rkey TID: `{ deviceId: 1, preKeyId, publicKey, formatVersion: 1 }`
- `is.neuros.atsignal.message` / rkey TID: `{ tag, envelopeType, ciphertext, formatVersion: 1 }`
- `is.neuros.atsignal.groupState` / rkey = `groupStateRkey(groupId)` (one-way; the groupId itself is secret because it keys the group tag and the state encryption): `{ epoch, stateCiphertext: sealGroupState(...), formatVersion: 1 }`

`envelopeType` values: `firstContact` (a libsignal PreKeySignalMessage under the first-contact tag), `prekey` (PreKeySignalMessage under a pair tag), `whisper` (SignalMessage), `senderKey` (SenderKeyMessage under a group tag).

## AppView API

`GET {appviewUrl}/xrpc/is.neuros.atsignal.getMessagesByTag?tags=<b64url>&tags=<b64url>&cursor=<c>&limit=<n>` returns
`{ cursor?: string, messages: [{ did, rkey, cid, tag: {$bytes}, envelopeType, ciphertext: {$bytes}, indexedAt }] }`, oldest first.
The cursor is the AppView's internal monotonically increasing row id, as a decimal string. `GET {appviewUrl}/health` returns `{ ok: true, indexed: <count>, lastSeq: <relay seq or null> }`.

## Toy rules

- Exactly one device per account, `deviceId = 1`. libsignal address = `ProtocolAddress.new(did, 1)`.
- Sender identity comes from the repo the record is in (the `did` in the AppView result).
- Inbox tags: own first-contact tag, plus `pairTag(seed, contactDid, myDid, w)` for w in {current, current-1}, plus `groupTag(groupId, w)` for each group, same two windows.
