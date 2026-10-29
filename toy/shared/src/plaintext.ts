import * as dagCbor from '@ipld/dag-cbor'
import { lexicons } from './lexicons.ts'

export type Text = { $type: 'is.neuros.atsignal.defs#text'; text: string }
export type ConversationInit = { $type: 'is.neuros.atsignal.defs#conversationInit'; tagSeed: Uint8Array }
export type SenderKeyDistribution = {
  $type: 'is.neuros.atsignal.defs#senderKeyDistribution'
  groupId: string
  distributionMessage: Uint8Array
}
export type GroupAction = {
  action: 'addMember' | 'removeMember' | 'addAdmin' | 'removeAdmin' | (string & {})
  did: string
}
export type GroupChange = {
  $type: 'is.neuros.atsignal.defs#groupChange'
  groupId: string
  epoch: number
  actions: GroupAction[]
  signerDid: string
  signature: Uint8Array
}
export type GroupSnapshot = {
  $type: 'is.neuros.atsignal.defs#groupSnapshot'
  groupId: string
  epoch: number
  members: string[]
  admins: string[]
  title?: string
}
export type Content = Text | ConversationInit | SenderKeyDistribution | GroupChange | GroupSnapshot

const CONTENT_TYPES = new Set<string>([
  'is.neuros.atsignal.defs#text',
  'is.neuros.atsignal.defs#conversationInit',
  'is.neuros.atsignal.defs#senderKeyDistribution',
  'is.neuros.atsignal.defs#groupChange',
  'is.neuros.atsignal.defs#groupSnapshot',
])

/** Drops `undefined` object properties (DAG-CBOR refuses them). Leaves bytes alone. */
export function stripUndefined<T>(value: T): T {
  if (Array.isArray(value)) return value.map(stripUndefined) as T
  if (value !== null && typeof value === 'object' && !(value instanceof Uint8Array)) {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = stripUndefined(v)
    return out as T
  }
  return value
}

/** Throws if `value` does not validate against the given lexicon object def. */
export function assertValidDef(lexUri: string, value: unknown): void {
  const res = lexicons.validate(lexUri, value)
  if (!res.success) throw new Error(`invalid ${lexUri}: ${res.error.message}`)
}

function assertValidPlaintext(value: unknown): asserts value is { content: Content } {
  assertValidDef('is.neuros.atsignal.defs#plaintext', value)
  // The lexicon union is open; we only accept the five known content types.
  const type = (value as { content: { $type?: unknown } }).content.$type
  if (typeof type !== 'string' || !CONTENT_TYPES.has(type)) {
    throw new Error(`invalid is.neuros.atsignal.defs#plaintext: unknown content $type ${JSON.stringify(type)}`)
  }
}

/** Validates against defs#plaintext, then DAG-CBOR encodes `{ content }`. */
export function encodePlaintext(content: Content): Uint8Array {
  const value = { content: stripUndefined(content) }
  assertValidPlaintext(value)
  return dagCbor.encode(value)
}

/** DAG-CBOR decodes, then validates against defs#plaintext. Returns the content. */
export function decodePlaintext(bytes: Uint8Array): Content {
  const value: unknown = dagCbor.decode(bytes)
  assertValidPlaintext(value)
  return value.content
}

/**
 * Bytes the signer signs: DAG-CBOR of the change without `signature`.
 * `signature` is dropped even if passed at runtime, and `$type` is always set to
 * defs#groupChange so signer and verifier agree regardless of how they built the object.
 */
export function groupChangeSigningBytes(change: Omit<GroupChange, 'signature'>): Uint8Array {
  const { signature: _ignored, ...rest } = change as Partial<GroupChange>
  const unsigned = stripUndefined({ ...rest, $type: 'is.neuros.atsignal.defs#groupChange' as const })
  // Validate the shape with a placeholder signature (the real one doesn't exist yet).
  assertValidDef('is.neuros.atsignal.defs#groupChange', { ...unsigned, signature: new Uint8Array(1) })
  return dagCbor.encode(unsigned)
}
