import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
import * as dagCbor from '@ipld/dag-cbor'
import { assertValidDef, stripUndefined, type GroupSnapshot } from './plaintext.ts'

// TOY ONLY: the key is derived from the groupId alone, so anyone who knows the
// groupId (it is the public record key) can decrypt. A real design would use a
// random group-state key distributed to members.
const NONCE_LEN = 12
const GCM_TAG_LEN = 16
const SNAPSHOT_TYPE = 'is.neuros.atsignal.defs#groupSnapshot'

function groupStateKey(groupId: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(groupId, 'utf8'), Buffer.alloc(0), 'atsignal-group-state', 32))
}

/** nonce(12) || AES-256-GCM ciphertext || GCM tag(16) of DAG-CBOR(snapshot). */
export function sealGroupState(groupId: string, snapshot: GroupSnapshot): Uint8Array {
  const value = stripUndefined({ ...snapshot, $type: SNAPSHOT_TYPE })
  assertValidDef(SNAPSHOT_TYPE, value)
  if (value.groupId !== groupId) throw new Error(`snapshot groupId ${value.groupId} != ${groupId}`)
  const nonce = randomBytes(NONCE_LEN)
  const cipher = createCipheriv('aes-256-gcm', groupStateKey(groupId), nonce)
  const ct = Buffer.concat([cipher.update(dagCbor.encode(value)), cipher.final(), cipher.getAuthTag()])
  return new Uint8Array(Buffer.concat([nonce, ct]))
}

export function openGroupState(groupId: string, sealed: Uint8Array): GroupSnapshot {
  if (sealed.length < NONCE_LEN + GCM_TAG_LEN) throw new Error('group state ciphertext too short')
  const nonce = sealed.subarray(0, NONCE_LEN)
  const ct = sealed.subarray(NONCE_LEN, sealed.length - GCM_TAG_LEN)
  const tag = sealed.subarray(sealed.length - GCM_TAG_LEN)
  const decipher = createDecipheriv('aes-256-gcm', groupStateKey(groupId), nonce)
  decipher.setAuthTag(tag)
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]) // throws on tamper / wrong key
  const value: unknown = dagCbor.decode(new Uint8Array(pt))
  assertValidDef(SNAPSHOT_TYPE, value)
  const snapshot = value as GroupSnapshot
  if (snapshot.$type !== SNAPSHOT_TYPE) throw new Error(`group state has $type ${JSON.stringify(snapshot.$type)}`)
  if (snapshot.groupId !== groupId) throw new Error(`group state groupId ${snapshot.groupId} != ${groupId}`)
  return snapshot
}
