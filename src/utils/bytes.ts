// Byte helpers neither @noble/hashes nor @scure/base provide — use those for
// the rest.

export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i])

/**
 * Orders byte arrays lexicographically, a shorter prefix first — the order
 * canonical RRsets are sorted in (RFC 4034 §6.3).
 */
export const compareBytes = (a: Uint8Array, b: Uint8Array): number => {
  const length = Math.min(a.length, b.length)
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i]
  }
  return a.length - b.length
}
