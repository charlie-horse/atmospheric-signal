// Rotating pairwise tags (design doc §2) and the public first-contact tag.
import { createHmac, createHash } from 'node:crypto'

export const TAG_LEN = 16
export const WINDOW_MS = 60 * 60 * 1000 // tags rotate hourly

export const windowOf = (ms) => Math.floor(ms / WINDOW_MS)

// Public: anyone who knows the recipient DID can compute it (accepted leak, decision 1).
export function firstContactTag(recipientDid) {
  return createHash('sha256').update(`atsignal/first-contact/v1\0${recipientDid}`).digest().subarray(0, TAG_LEN)
}

// Private: only holders of tagSeed can compute or link these.
export function pairTag(tagSeed, fromDid, toDid, window) {
  return createHmac('sha256', tagSeed)
    .update(`atsignal/pair/v1\0${fromDid}\0${toDid}\0${window}`)
    .digest()
    .subarray(0, TAG_LEN)
}
