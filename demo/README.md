# atsignal toy demo

Runs the design in `docs/signal-on-atproto.md` end to end in one process, with real Signal crypto and a fake ATProto PDS.

```sh
cd demo
npm install
npm run demo   # exits 0 and prints PASS when every check holds
```

Needs Node 22+. `@signalapp/libsignal-client` ships prebuilt binaries for linux-x64, macOS and Windows, so no Rust toolchain is needed.

## What is real and what is faked

| Part | Status |
|---|---|
| Signal crypto: PQXDH (X25519 + Kyber), Double Ratchet, safety numbers | Real (`@signalapp/libsignal-client`) |
| Record schemas | Real: every record and every decrypted plaintext is validated against `lexicons/is/neuros/atsignal/*` |
| Plaintext encoding | Real DAG-CBOR (`@ipld/dag-cbor`) |
| PDS | Toy, in memory: per-DID repos, TIDs, unauthenticated reads, a firehose event per write. No MST, signed commits, CAR, auth or rate limits |
| AppView | Toy: indexes `is.neuros.atsignal.message` by `tag` from the firehose and keeps every body it saw |
| Clock | Fake, so the demo can jump an hour and show tag rotation |

## What the scenario shows

1. Alice and Bob publish `identity`, `device` (signed + Kyber prekeys) and one-time `preKey` records.
2. Alice builds a prekey bundle from Bob's public records and sends a `firstContact` message carrying `defs#conversationInit` (the 32-byte `tagSeed`).
3. Bob finds it by his public first-contact tag, deletes the used one-time prekey record, and from then on both sides use rotating pairwise tags (HMAC of `tagSeed` over direction and hour).
4. The tag changes when the hour changes.
5. Both sides compute the same safety number from the identity records.
6. The observer view: sender, tags, envelope types and sizes are public; Bob's DID never appears in Alice's repo.
7. Deleting a message record removes it from the PDS, but the indexer still has a copy (decision 5).

## Choices the doc leaves open (made here, flag before relying on them)

- **Tags.** `firstContactTag = sha256("atsignal/first-contact/v1\0" + did)[:16]`; `pairTag = HMAC-SHA256(tagSeed, "atsignal/pair/v1\0" + from + "\0" + to + "\0" + hourWindow)[:16]`. Receivers check the current and previous window.
- **Sender device.** A message record does not say which device sent it (open question 8). The demo assumes one device per account and reads its id from the sender's `device` record.
- **Identity changes.** Trust on first use; a changed identity key is refused.
- **Prekey race (open question 11).** A sender takes the first listed `preKey` record; nothing stops two senders taking the same one.

## Findings so far

- PQXDH prekey messages are about 1.8 KB (the Kyber ciphertext); Double Ratchet messages are about 170 B. Both are far under the 64 KiB `ciphertext` cap.
- Every message before the recipient's first reply is a libsignal PreKey message. The demo labels the very first one `firstContact` and the rest `prekey`; the receiver uses the same decrypt path for both.

## Groups (sections 8–13)

Alice creates a group with Bob and Carol, everyone sends a sender-key message, Alice removes Carol (everyone rekeys, Carol can't decrypt), Alice adds Dave (Dave reads only post-join messages), and forged `groupChange`s from a non-admin are rejected. Code: `src/groups.js`.

Our-design choices (not in the doc): group tag = `HMAC(groupTagSeed, "atsignal/group/v1\0" + senderDid + "\0" + hour)[:16]`, with a fresh seed per epoch; `groupChange` signs `"atsignal/groupChange/v1\0" + DAG-CBOR(change without signature)` and is verified against the pinned (safety-number) key; the smaller DID starts any missing pairwise session.

### Lexicon gaps found

- **No def carries group secrets** (group tag seed, group-state key, snapshot location). The demo uses a labelled demo-only `$type: "demo.gap#groupSecrets"`. Suggest a `defs#groupWelcome`.
- **`defs#plaintext` union is open**, so validation accepts any `$type`. Consider `closed: true`.
- `defs#text` has no group context; the group is inferred from the tag.
- `groupChange` signing input is unspecified, and it does not bind the previous state (two admins at epoch N+1 split the group).
- `senderKeyDistribution` has no epoch; `groupSnapshot` is unsigned; `groupState` goes stale if a non-creator admin changes membership; `groupAction` has no "leave".

### Design issues found

- **Concurrent first contacts collide on one-time prekeys** (open question 11, hit for real): two members contacting a joiner at once take the same `preKey` and the second decrypt fails. The demo skips one-time prekeys for group-triggered sessions.
- Group creation/joins cause a burst of public first-contact tags at one DID, which links the senders as a group.
- `envelopeType: "senderKey"` and `groupState.epoch` are public, so observers see which records are group messages and when membership changes.
- Rekeying is about N×N pairwise messages per change.
- libsignal's `SenderKeyStore` has no delete; removed members' old keys are rejected only by a membership check on the repo DID.
