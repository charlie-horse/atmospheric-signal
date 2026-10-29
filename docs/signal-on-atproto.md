# Signal on ATProto: design evaluation

Status: decisions resolved 2026-10-29. Lexicons in lexicons/is/neuros/atsignal/. No implementation yet.

**Verification key.** Every ATProto claim cites a URL. Each claim is marked VERIFIED (read in a fetched spec or source page) or UNVERIFIED (not confirmed; treat as open). Quotes came from model-processed fetches and are not guaranteed character-exact. Re-check any quote before this doc is shared.

## Summary

- ATProto stores each account's data in one signed repository, and public repos are fetchable without auth. So any ciphertext we write is public, along with its metadata. This is the main constraint. We accept it for now (decision 1).
- Signal's keys fit ATProto's identity model poorly. The DID document only accepts a defined set of key entries, so the Signal identity key lives in a repo record, `is.neuros.atsignal.identity` (decision 3).
- Messages are addressed by a rotating pairwise tag, not the recipient DID (decision 2). After first contact, the recipient is not public. The sender, timing, sizes, and first-contact edges still are.
- Group membership lives in encrypted state. Removal makes every remaining member rotate their sender key (decision 4).
- Deletion removes access, not copies. Confidentiality must come from Signal's encryption, not from the server (decision 5).
- The ATProto private-data work (Spaces) is alpha, unencrypted, and not for production. We plan to move to it later and shape the design so the move is cheap (see "Spaces migration path").

## 1. Identity

**Facts.**
- ATProto accepts `did:plc` and `did:web`. The DID document defines `verificationMethod` entries (`Multikey`) and `service` entries. The signing key is the first `verificationMethod` whose id ends in `#atproto`. Other entries are ignored. (VERIFIED: https://atproto.com/specs/did)
- Handles are bound to DIDs in both directions: a DNS `_atproto` TXT record or `/.well-known/atproto-did`, confirmed against the DID document. (VERIFIED: https://atproto.com/specs/handle)
- `did:plc` control rests in rotation keys, which sign update operations. Updates go through a central directory that keeps a transparent log per DID. (PARTIAL: https://github.com/did-method-plc/did-method-plc. Operation validation rules, the recovery window, and who operates the production directory are UNVERIFIED.)
- Labels use a second key, `#atproto_label`. Verifiers are told not to fall back to other keys in the DID document. (VERIFIED: https://atproto.com/specs/label)
- Where the account signing key is stored, and whether it signs anything besides repo commits, is not stated. (UNVERIFIED: https://atproto.com/specs/account)

**Mapping.**
- DID → the account. The DID document carries the ATProto signing key and the PDS endpoint. It does not carry a Signal key, because the spec defines no entry for one (VERIFIED for the defined entries; whether extra entries are safe is UNVERIFIED).
- Signal identity key (Curve25519, XEdDSA-signed; VERIFIED: https://signal.org/docs/specifications/x3dh/) → the record `is.neuros.atsignal.identity`, record key `literal:self` (one per account). It is public, which is fine: Signal already publishes identity keys in prekey bundles. It also reserves a `firstContactKey` field for a private first-contact scheme later (§2).
- Devices and prekeys → `is.neuros.atsignal.device` (one record per device, holding its signed prekey and optional Kyber prekey) and `is.neuros.atsignal.preKey` (one-time prekeys). These are public too, as in Signal's prekey bundles.

**Key directory and update authority.**
- The directory is the user's repo. Writes to it are authorized by the account's ATProto signing key and the PDS that hosts the repo. Whoever can write that repo can replace the Signal identity key.
- PDS trust is the weak point. Repo commits are signed, but who holds the private signing key is UNVERIFIED. If the PDS holds it, the PDS can substitute keys.
- Mitigation: clients verify identity keys out of band (Signal safety numbers, derived from identity keys; VERIFIED in code: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/fingerprint.rs) and treat a changed key as an alert.

**Device mapping.** Signal sessions are per device. We list devices in `is.neuros.atsignal.device` records. How this matches Signal's own DID → device-ID model is UNVERIFIED: the Sesame spec was not fetched.

## 2. Message storage

**Facts.**
- Records are keyed by `<collection>/<rkey>` in a Merkle Search Tree. Creating, updating, or deleting a record changes the root, and each version is a signed commit. (VERIFIED: https://atproto.com/specs/repository)
- Record keys allow `A-Za-z0-9 . - _ : ~`, length 1 to 512. (VERIFIED: https://atproto.com/specs/record-key)
- NSIDs cannot contain `:`. (VERIFIED: https://atproto.com/specs/nsid) So a collection per recipient DID does not work.
- Large media goes in blobs, referenced by hash, and blobs become publicly accessible once referenced. (VERIFIED: https://atproto.com/specs/blob)
- `getRepo` is unauthenticated and returns all records and the signed commit. (VERIFIED: https://atproto.com/specs/sync)
- The record size limit, whether getRecord needs auth, and whether writes to one repo are serialized into one commit are UNVERIFIED.

**Schema.** One collection, `is.neuros.atsignal.message`, record key `tid`. This supersedes the earlier draft (fields `recipient`, `ciphertext`, `seq`, `senderKeyId`, `formatVersion`; rkey `<recipientDid>:<seq>`), which put the recipient in public view.

| Field | Type | Purpose |
|---|---|---|
| `tag` | bytes, 16–32 | Rotating pairwise address (see below). Public, but only the pair can link tags. |
| `envelopeType` | string: `prekey` / `whisper` / `senderKey` / `firstContact` | Tells the recipient which libsignal decrypt path to use. |
| `ciphertext` | bytes, ≤64 KiB | libsignal ciphertext (opaque). Larger content goes in an encrypted blob. |
| `formatVersion` | integer | Our own version field. libsignal serialization is unstable (see §6). |

The recipient, the ratchet counter, and the sender-key distribution id are inside the ciphertext. Sender DID is implied by the repo.

**Addressing: rotating pairwise tag.**
- The first message of a conversation carries a random 32-byte `tagSeed` inside the ciphertext (`defs#conversationInit`).
- Both parties derive each tag as a truncated HMAC of the `tagSeed` over the direction and a time window. Tags rotate, and only the pair can link them.
- First contact: the sender has no shared seed yet. It uses a public first-contact tag derived from the recipient's DID, with `envelopeType` `firstContact`. This reveals that someone started a conversation with that recipient. We accept this under decision 1.
- The identity record reserves a `firstContactKey` field so a private first-contact scheme can be added later.
- Recipients find messages by scanning or indexing the tags they expect: their current pairwise tags and their own first-contact tag.

**Parallel writes.** Each message is a separate record with its own TID, so writes do not conflict. However, they all land in one repo, which the PDS commits in sequence, and write rate limits apply (UNVERIFIED). Parallelism is capped at the PDS, not by the schema.

**Recipient reads.** There is no per-recipient inbox in ATProto. A recipient must find records with its expected tags across senders' repos. Options: an AppView indexes the firehose by `tag` (the firehose carries full commit data; VERIFIED: https://atproto.com/specs/sync), or each recipient polls the repos of known contacts. The AppView option is an inference, not a verified capability. An indexer sees tags but cannot link them to recipients, except for first-contact tags.

**Sealed sender does not help here.** Sealed sender hides the sender from the Signal server (VERIFIED in code: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/sealed_sender.rs). In ATProto the repo owner is the sender, so the sender is public.

## 3. Groups

**Facts.** Sender Keys: each sender holds a chain key with an iteration counter. Each group message advances the chain (VERIFIED in code, sender_keys.rs above). The SenderKeyDistributionMessage (SKDM) format and its delivery over pairwise sessions are UNVERIFIED: the Signal docs index has no sender-key page.

**Mapping.**
- Group message: one `is.neuros.atsignal.message` record in the sender's repo, `envelopeType` `senderKey`. Recipients fetch the record once. This is one write per message, not one per member.
- SKDM: sent pairwise to each member as a message record, over the pairwise session. It carries the chain key and iteration inside the ciphertext.
- Membership lives in encrypted state held by each member. There is no public membership record.
- Membership changes travel as encrypted control messages (`defs#groupChange`), sent pairwise through message records. Each is signed by an admin's Signal identity key. A client applies a change only if the signer is an admin in its current state and the change's epoch is the current epoch + 1.
- The creator keeps an encrypted snapshot of the group state in `is.neuros.atsignal.groupState`, record key = a random group id. Joiners use it to catch up on membership, not on message history.

**Group policy (decision 4; our design, not spec):**
- An admin set may change membership. Only changes signed by a current admin are applied.
- Remove: every remaining member rotates their sender key and sends a new SKDM to every remaining member. That is about N×N pairwise messages per removal. Signal's own rekey rule is UNVERIFIED; this rule is ours.
- Join: members rotate their sender keys, so the joiner can read only messages sent after joining. New members get no history.

## 4. Metadata exposure

| Observer | What it sees per message |
|---|---|
| Sender's PDS | Everything in the repo, including ciphertext, tag, envelope type, timestamps, sizes, and the requester's IP. It can link a first-contact tag to its recipient. |
| Relays (firehose) | Commit events carry the record data as a CAR slice (VERIFIED: https://atproto.com/specs/sync). Relays do not validate records against lexicons (VERIFIED: same). So every relay sees every ciphertext, tag, and sender. |
| AppView | Whatever it indexes. Given the firehose content, that includes everything above. |
| Anyone | `getRepo` is unauthenticated (VERIFIED above). Mirrors must not redistribute snapshots in bulk, but this is a norm, not an enforcement mechanism (VERIFIED: https://atproto.com/specs/sync). |

Summary: with rotating tags, the recipient DID is no longer public after first contact. The sender DID, message timing, ciphertext sizes, and first-contact edges (who started a conversation with whom) are still public. Confidentiality of content holds if Signal's encryption is correct. Confidentiality of the social graph holds only partly.

## 5. Deletion

- `deleteRecord` changes the repo root, and mirrors are required to follow deletions "within seconds or minutes." (VERIFIED: https://atproto.com/specs/sync)
- The spec does not require relays or AppViews to purge copies already taken. (UNVERIFIED that copies are purged; assume they persist.)
- Account deactivation removes public data (VERIFIED: https://atproto.com/specs/sync), again with the same copy caveat.
- The Spaces alpha has no space repo deletion operation (VERIFIED: https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data).

**Consequence (decision 5).** "Delete" means removing access. The ciphertext may remain on relays indefinitely. Real erasure relies on deleting the message keys on each client (forward secrecy). Server deletion is a courtesy, not a guarantee.

## Spaces migration path

Sources: the permissioned-data proposal, a draft (https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data), and the Spaces alpha announcement (https://atproto.com/blog/atproto-spaces-alpha). The alpha is unencrypted, and the announcement says "you absolutely should not run production code against it." We do not build against it. We shape the design so a later move is cheap.

- Spaces keep lexicon-typed records, and "all spaces may contain records of any type." So the same `is.neuros.atsignal.*` schemas carry over. (VERIFIED: both sources above)
- Space record URIs have a different shape: `at://{spaceDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}`. So no record body stores an AT-URI. Cross-references use `defs#recordRef` {`did`, `collection`, `rkey`}. (VERIFIED: proposal above)
- Record keys are opaque. We do not encode meaning in them. (VERIFIED: proposal above)
- There is no relay firehose for spaces. Apps pull from each PDS after `registerNotify`. So storage and sync go behind one swappable interface. (VERIFIED: both sources above)
- Spaces give access control, not confidentiality, and space data is unsigned. So Signal encryption and identity-key signatures stay. (VERIFIED: both sources above)
- Each conversation or group maps to one future space. The space-type NSID `is.neuros.atsignal.space.conversation` is reserved. It is not written as a lexicon, because the space-type format exists only in the proposal.
- Whether a record lexicon needs any annotation to be used in a space. (UNVERIFIED)

## 6. Open questions

| # | Question | Status |
|---|---|---|
| 1 | Who holds the account's ATProto signing key: the user, or the PDS? | UNVERIFIED |
| 2 | Does getRecord require auth? | UNVERIFIED |
| 3 | Do writes to one repo serialize into one commit, and what are the write rate limits? | UNVERIFIED |
| 4 | Can an AppView index an arbitrary collection (here, by `tag`)? | UNVERIFIED |
| 5 | Are extra DID-document entries (e.g. a Signal key) safe for verifiers to ignore? | UNVERIFIED (moot: the key is in a repo record) |
| 6 | Spaces (private data): alpha, unencrypted, not for production. Is it on a path to confidentiality? | VERIFIED as alpha and unencrypted (https://atproto.com/blog/atproto-spaces-alpha); the roadmap lists permissioned data as planned (https://atproto.com/blog/2026-spring-roadmap); the proposal is a draft (https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) |
| 7 | Do relays retain full record bodies, and for how long? | UNVERIFIED |
| 8 | The DID → device-ID mapping, and the SKDM format. | UNVERIFIED (Sesame and SKDM not fetched). The rekey rule is now our policy (§3). |
| 9 | Is libsignal's session and sender-key serialization stable? | VERIFIED as unversioned protobuf, AGPL-3.0, with no stability promise (https://github.com/signalapp/libsignal) |
| 10 | May NSID segments contain `:`? | VERIFIED: no (https://atproto.com/specs/nsid) |
| 11 | One-time prekey race: two senders fetch the same public `preKey` record before the owner deletes it. | Design question |
| 12 | First-contact tags leak who started a conversation with whom. | Accepted for now (decision 1); private scheme open (`firstContactKey` reserved) |
| 13 | Record size cap. We set `ciphertext` ≤64 KiB. | UNVERIFIED. The style guide says bytes are for constrained sizes and larger data should use blobs (https://atproto.com/guides/lexicon-style-guide) |

Private-data question (6) is the one that could change the design. Until Spaces is production-ready and encrypted, all content must be Signal-encrypted before it is written. See "Spaces migration path."

## Decisions (resolved 2026-10-29)

1. **Public metadata.** Accepted for now. Plan to move to ATProto Spaces once it is production-ready. Do not build against the Spaces alpha.
2. **Direct-message addressing.** Stays private: a rotating pairwise tag. No recipient DID in plaintext.
3. **Identity-key location.** A repo record: `is.neuros.atsignal.identity`, record key `literal:self`.
4. **Groups.** An admin set may change membership. On removal, every remaining member rotates their sender key. New members get no history: members rotate on join.
5. **Deletion.** Deletion means removing access. Erasure relies on client-side key deletion.
