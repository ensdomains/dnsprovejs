/**
 * The boundary with dns-packet. It reads and writes through Buffer methods
 * (`readUInt16BE`, `copy`, …) rather than Uint8Array ones, so every byte array
 * handed to it has to be a Buffer — including binary record fields it encodes.
 * This is the only module that deals in Buffers. It imports `buffer` the way
 * dns-packet itself does, never relying on Node's global (browsers have none):
 * runtimes resolve the built-in, bundlers the npm polyfill. The `node:` form
 * would defeat that, since bundlers never map it to a package.
 */
import { Buffer } from 'buffer'
import * as dnsPacket from 'dns-packet'
import type { Answer, DecodedPacket, Packet, RrsigData } from 'dns-packet'

/** The Buffer type the dns-packet typings expect. */
type PacketBuffer = Parameters<typeof dnsPacket.decode>[0]

interface Codec<T> {
  encode: ((value: T) => PacketBuffer) & { bytes: number }
  decode: ((buf: PacketBuffer, offset?: number) => T) & { bytes: number }
}

// dns-packet also exports a codec per record type and for names, which
// @types/dns-packet leaves undeclared.
const packet = dnsPacket as typeof dnsPacket & {
  name: Codec<string>
  answer: Codec<Answer>
  rrsig: Codec<RrsigData>
  record(type: string): Codec<unknown>
}

export const { DNSSEC_OK, RECURSION_DESIRED } = dnsPacket

/**
 * A Buffer view over the same memory as `bytes`, for handing to dns-packet or
 * storing in a record it will encode.
 */
export const toBuffer = (bytes: Uint8Array): PacketBuffer =>
  (Buffer.isBuffer(bytes)
    ? bytes
    : Buffer.from(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      )) as PacketBuffer

export const encodePacket = (message: Packet): Uint8Array =>
  dnsPacket.encode(message)

export const decodePacket = (bytes: Uint8Array): DecodedPacket =>
  dnsPacket.decode(toBuffer(bytes))

/** The uncompressed wire form of a domain name (RFC 1035 §3.1). */
export const encodeName = (name: string): Uint8Array => packet.name.encode(name)

/** The wire form of a resource record (RFC 1035 §4.1.3). */
export const encodeAnswer = (record: Answer): Uint8Array =>
  packet.answer.encode(record)

/** Decodes the resource record at `offset`, and how many bytes it spans. */
export const decodeAnswer = (
  bytes: Uint8Array,
  offset: number,
): { record: Answer; length: number } => ({
  record: packet.answer.decode(toBuffer(bytes), offset),
  length: packet.answer.decode.bytes,
})

/** A record's RDATA, without the RDLENGTH prefix dns-packet's codecs emit. */
export const encodeRdata = (
  record: Exclude<Answer, { type: 'OPT' }>,
): Uint8Array => packet.record(record.type).encode(record.data).subarray(2)

/**
 * The part of an RRSIG's RDATA that its signature covers: every field but the
 * signature itself (RFC 4034 §3.1.8.1).
 */
export const encodeRrsigPrefix = (data: RrsigData): Uint8Array =>
  packet.rrsig
    .encode({ ...data, signature: toBuffer(new Uint8Array()) })
    .subarray(2)

/**
 * Reads the RRSIG RDATA prefix `encodeRrsigPrefix` writes from the start of
 * `bytes`, with an empty signature, and how many bytes it spans.
 */
export const decodeRrsigPrefix = (
  bytes: Uint8Array,
): { data: RrsigData; length: number } => {
  // The fields are fixed-width up to the signer's name, which ends the prefix
  // (RFC 4034 §3.1). Frame exactly those bytes with the RDLENGTH dns-packet's
  // codec expects, so none are left over to read as a signature.
  packet.name.decode(toBuffer(bytes), 18)
  const length = 18 + packet.name.decode.bytes
  const framed = new Uint8Array(2 + length)
  new DataView(framed.buffer).setUint16(0, length)
  framed.set(bytes.subarray(0, length), 2)
  return { data: packet.rrsig.decode(toBuffer(framed)), length }
}
