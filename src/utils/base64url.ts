/**
 * Converts a Buffer to base64url encoding.
 * Manual conversion needed since polyfills don't support buffer.toString('base64url') yet.
 */
export function bufferToBase64url(buffer: Buffer): string {
  const base64 = buffer.toString('base64')
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
