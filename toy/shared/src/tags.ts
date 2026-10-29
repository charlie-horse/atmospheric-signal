import { createHash, createHmac } from 'node:crypto'

export const TAG_WINDOW_MS = 3_600_000
const TAG_LEN = 16

export function currentWindow(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / TAG_WINDOW_MS)
}

function checkWindow(window: number): string {
  if (!Number.isSafeInteger(window) || window < 0) {
    throw new Error(`tag window must be a non-negative integer, got ${window}`)
  }
  return String(window)
}

function first16(buf: Uint8Array): Uint8Array {
  return new Uint8Array(buf.subarray(0, TAG_LEN))
}

/** HMAC-SHA256(tagSeed, "atsignal-pair\0" + from + "\0" + to + "\0" + window)[0..16]. Direction matters. */
export function pairTag(tagSeed: Uint8Array, fromDid: string, toDid: string, window: number): Uint8Array {
  const msg = `atsignal-pair\0${fromDid}\0${toDid}\0${checkWindow(window)}`
  return first16(createHmac('sha256', tagSeed).update(msg, 'utf8').digest())
}

/** SHA-256("atsignal-first-contact\0" + recipientDid)[0..16]. Public: anyone can compute it. */
export function firstContactTag(recipientDid: string): Uint8Array {
  return first16(createHash('sha256').update(`atsignal-first-contact\0${recipientDid}`, 'utf8').digest())
}

/** HMAC-SHA256(utf8(groupId), "atsignal-group\0" + window)[0..16]. */
export function groupTag(groupId: string, window: number): Uint8Array {
  const msg = `atsignal-group\0${checkWindow(window)}`
  return first16(createHmac('sha256', Buffer.from(groupId, 'utf8')).update(msg, 'utf8').digest())
}

/**
 * Record key for a group's is.neuros.atsignal.groupState record:
 * base64url(HMAC-SHA256(utf8(groupId), "atsignal-group-state-rkey")[0..16]), 22 chars.
 * The groupId keys the group tag and the group-state encryption, so it must never appear in public.
 */
export function groupStateRkey(groupId: string): string {
  const mac = createHmac('sha256', Buffer.from(groupId, 'utf8')).update('atsignal-group-state-rkey', 'utf8').digest()
  return tagToParam(first16(mac))
}

/** base64url without padding. */
export function tagToParam(tag: Uint8Array): string {
  return Buffer.from(tag.buffer, tag.byteOffset, tag.byteLength).toString('base64url')
}

export function tagFromParam(s: string): Uint8Array {
  // Buffer's decoder silently skips junk, so be strict here.
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new Error(`invalid base64url tag: ${JSON.stringify(s)}`)
  }
  return new Uint8Array(Buffer.from(s, 'base64url'))
}
