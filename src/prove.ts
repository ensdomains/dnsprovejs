import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js'
import { base64, base64urlnopad, utf8 } from '@scure/base'
import type {
  Answer,
  DnskeyAnswer,
  DSAnswer,
  OptAnswer,
  Packet,
  RecordType,
  RrsigAnswer,
  TxtData,
} from 'dns-packet'
import { logger } from './log.js'
import {
  DNSSEC_OK,
  decodeAnswer,
  decodePacket,
  decodeRrsigPrefix,
  encodeAnswer,
  encodeName,
  encodePacket,
  encodeRdata,
  encodeRrsigPrefix,
  RECURSION_DESIRED,
  toBuffer,
} from './packet.js'
import { compareBytes, equalBytes } from './utils/bytes.js'

/** Any resource record but the OPT pseudo-record, which is never signed. */
export type RecordAnswer = Exclude<Answer, OptAnswer>

type AnswerOf<T extends RecordType> = Extract<RecordAnswer, { type: T }>

/** A decoded DNS response — dns-packet sets `rcode`, its typings omit it. */
export type DnsResponse = Packet & { rcode?: string }

export interface DigestAlgorithm {
  name: string
  f: (data: Uint8Array, digest: Uint8Array) => boolean
}

export interface SignatureAlgorithm {
  name: string
  f: (key: Uint8Array, data: Uint8Array, signature: Uint8Array) => boolean
}

const rootDs = (keyTag: number, digest: string): DSAnswer => ({
  name: '.',
  type: 'DS',
  class: 'IN',
  data: {
    keyTag,
    algorithm: 8,
    digestType: 2,
    digest: toBuffer(hexToBytes(digest)),
  },
})

export const DEFAULT_TRUST_ANCHORS: DSAnswer[] = [
  rootDs(
    19036,
    '49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5',
  ),
  rootDs(
    20326,
    'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
  ),
]

/** The key tag of a DNSKEY (RFC 4034 appendix B). */
export function getKeyTag(key: DnskeyAnswer): number {
  let keyTag = 0
  for (const [i, byte] of encodeRdata(key).entries()) {
    keyTag += i & 1 ? byte : byte << 8
  }
  keyTag += (keyTag >> 16) & 0xffff
  return keyTag & 0xffff
}

const txtToString = (data: TxtData): string =>
  (Array.isArray(data) ? data : [data])
    .map((t) => `"${typeof t === 'string' ? t : utf8.encode(t)}"`)
    .join(' ')

function answerToString(a: Answer): string {
  if (a.type === 'OPT') return `${a.name} OPT`
  const prefix = `${a.name} ${a.ttl} ${a.class} ${a.type}`
  switch (a.type) {
    case 'DNSKEY':
      return `${prefix} ${a.data.flags} 3 ${a.data.algorithm} ${base64.encode(
        a.data.key,
      )}; keyTag=${getKeyTag(a)}`
    case 'DS':
      return `${prefix} ${a.data.keyTag} ${a.data.algorithm} ${
        a.data.digestType
      } ${bytesToHex(a.data.digest)}`
    case 'RRSIG': {
      const d = a.data
      return `${prefix} ${d.typeCovered} ${d.algorithm} ${d.labels} ${
        d.originalTTL
      } ${d.expiration} ${d.inception} ${d.keyTag} ${
        d.signersName
      } ${base64.encode(d.signature)}`
    }
    case 'TXT':
      return `${prefix} ${txtToString(a.data)}`
    default:
      return typeof a.data === 'string' ? `${prefix} ${a.data}` : prefix
  }
}

export const answersToString = (answers: Answer[]): string =>
  answers.map(answerToString).join('\n')

/** A `sendQuery` for a DNS-over-HTTPS server's GET endpoint (RFC 8484). */
export function dohQuery(url: string) {
  return async function getDNS(q: Packet): Promise<DnsResponse> {
    const dns = base64urlnopad.encode(encodePacket(q))
    const response = await fetch(`${url}?dns=${dns}&ts=${Date.now()}`, {
      headers: {
        accept: 'application/dns-message',
      },
    })
    return decodePacket(new Uint8Array(await response.arrayBuffer()))
  }
}

export class SignedSet<T extends RecordAnswer> {
  records: T[]

  signature: RrsigAnswer

  constructor(records: T[], signature: RrsigAnswer) {
    this.records = records
    this.signature = signature
  }

  /** Rebuilds a set from `toWire()` output and the signature it carried. */
  static fromWire<T extends RecordAnswer>(
    data: Uint8Array,
    signature: Uint8Array,
  ): SignedSet<T> {
    const { data: rdata, length } = decodeRrsigPrefix(data)
    rdata.signature = toBuffer(signature)

    const records: T[] = []
    for (let offset = length; offset < data.length; ) {
      const { record, length: size } = decodeAnswer(data, offset)
      records.push(record as T)
      offset += size
    }

    const [first] = records
    return new SignedSet<T>(records, {
      name: first.name,
      type: 'RRSIG',
      class: first.class,
      data: rdata,
    })
  }

  toWire(withRrsig = true): Uint8Array {
    const rrset = concatBytes(
      ...this.records
        // https://tools.ietf.org/html/rfc4034#section-6
        .sort((a, b) => compareBytes(encodeRdata(a), encodeRdata(b)))
        .map((r) =>
          encodeAnswer(
            Object.assign(r, {
              name: r.name.toLowerCase(), // (2)
              ttl: this.signature.data.originalTTL, // (5)
            }),
          ),
        ),
    )
    return withRrsig
      ? concatBytes(encodeRrsigPrefix(this.signature.data), rrset)
      : rrset
  }
}

export interface ProvableAnswer<T extends RecordAnswer> {
  answer: SignedSet<T>
  proofs: SignedSet<DnskeyAnswer | DSAnswer>[]
}

export class ResponseCodeError extends Error {
  query: Packet

  response: DnsResponse

  constructor(query: Packet, response: DnsResponse) {
    super(`DNS server responded with ${response.rcode}`)
    this.name = 'ResponseError'
    this.query = query
    this.response = response
  }
}

export class NoValidDsError extends Error {
  keys: DnskeyAnswer[]

  constructor(keys: DnskeyAnswer[]) {
    super(
      `Could not find a DS record to validate any RRSIG on DNSKEY records for ${keys[0].name}`,
    )
    this.keys = keys
    this.name = 'NoValidDsError'
  }
}

export class NoValidDnskeyError<T extends RecordAnswer> extends Error {
  result: T[]

  constructor(result: T[]) {
    super(
      `Could not find a DNSKEY record to validate any RRSIG on ${result[0].type} records for ${result[0].name}`,
    )
    this.result = result
    this.name = 'NoValidDnskeyError'
  }
}

export const DEFAULT_DIGESTS: Record<number, DigestAlgorithm> = {
  1: {
    name: 'SHA1',
    f: () => true,
  },
  2: {
    name: 'SHA256',
    f: (data, digest) => equalBytes(digest, sha256(data)),
  },
}

export const DEFAULT_ALGORITHMS: Record<number, SignatureAlgorithm> = {
  5: {
    name: 'RSASHA1Algorithm',
    f: () => true,
  },
  7: {
    name: 'RSASHA1Algorithm',
    f: () => true,
  },
  8: {
    name: 'RSASHA256',
    f: () => true,
  },
  13: {
    name: 'P256SHA256',
    f: () => true,
  },
}

const isDnskeySet = (records: RecordAnswer[]): records is DnskeyAnswer[] =>
  records.every((r) => r.type === 'DNSKEY')

function groupBy<T>(values: T[], key: (value: T) => number): Map<number, T[]> {
  const groups = new Map<number, T[]>()
  for (const value of values) {
    const k = key(value)
    const group = groups.get(k)
    if (group) group.push(value)
    else groups.set(k, [value])
  }
  return groups
}

class DNSQuery {
  readonly #prover: DNSProver

  readonly #cache = new Map<string, DnsResponse>()

  constructor(prover: DNSProver) {
    this.#prover = prover
  }

  async queryWithProof<T extends RecordType>(
    qtype: T,
    qname: string,
  ): Promise<ProvableAnswer<AnswerOf<T>> | null> {
    const response = await this.dnsQuery(qtype, qname)
    const records = response.answers ?? []
    const answers = records.filter(
      (r): r is AnswerOf<T> => r.type === qtype && r.name === qname,
    )
    logger.info(`Found ${answers.length} ${qtype} records for ${qname}`)
    if (answers.length === 0) {
      return null
    }

    const sigs = records.filter(
      (r): r is RrsigAnswer =>
        r.type === 'RRSIG' && r.name === qname && r.data.typeCovered === qtype,
    )
    logger.info(`Found ${sigs.length} RRSIGs over ${qtype} RRSET`)

    // If the records are self-signed, verify with DS records
    if (
      isDnskeySet(answers) &&
      sigs.some((sig) => sig.name === sig.data.signersName)
    ) {
      logger.info(
        `DNSKEY RRSET on ${answers[0].name} is self-signed; attempting to verify with a DS in parent zone`,
      )
      return this.verifyWithDS(answers, sigs) as Promise<
        ProvableAnswer<AnswerOf<T>>
      >
    }
    return this.verifyRRSet(answers, sigs)
  }

  async verifyRRSet<T extends RecordAnswer>(
    answers: T[],
    sigs: RrsigAnswer[],
  ): Promise<ProvableAnswer<T>> {
    const { algorithms } = this.#prover
    for (const sig of sigs) {
      const algorithm: SignatureAlgorithm | undefined =
        algorithms[sig.data.algorithm]
      logger.info(
        `Attempting to verify the ${answers[0].type} RRSET on ${
          answers[0].name
        } with RRSIG=${sig.data.keyTag}/${
          algorithm?.name ?? sig.data.algorithm
        }`,
      )

      if (algorithm === undefined) {
        logger.info(
          `Skipping RRSIG=${sig.data.keyTag}/${sig.data.algorithm} on ${answers[0].type} RRSET for ${answers[0].name}: Unknown algorithm`,
        )
        continue
      }

      const ss = new SignedSet(answers, sig)
      const result = await this.queryWithProof('DNSKEY', sig.data.signersName)
      if (result === null) {
        throw new NoValidDnskeyError(answers)
      }
      const { answer, proofs } = result
      for (const key of answer.records) {
        if (this.verifySignature(ss, key)) {
          logger.info(
            `RRSIG=${sig.data.keyTag}/${algorithm.name} verifies the ${answers[0].type} RRSET on ${answers[0].name}`,
          )
          proofs.push(answer)
          return { answer: ss, proofs }
        }
      }
    }
    logger.warn(
      `Could not verify the ${answers[0].type} RRSET on ${answers[0].name} with any RRSIGs`,
    )
    throw new NoValidDnskeyError(answers)
  }

  async verifyWithDS(
    keys: DnskeyAnswer[],
    sigs: RrsigAnswer[],
  ): Promise<ProvableAnswer<DnskeyAnswer>> {
    const keyname = keys[0].name

    // Fetch the DS records to use
    let dses: DSAnswer[]
    let proofs: SignedSet<DnskeyAnswer | DSAnswer>[]
    if (keyname === '.') {
      dses = this.#prover.anchors
      proofs = []
    } else {
      const response = await this.queryWithProof('DS', keyname)
      if (response === null) {
        throw new NoValidDsError(keys)
      }
      dses = response.answer.records
      proofs = [...response.proofs, response.answer]
    }

    const keysByTag = groupBy(keys, getKeyTag)
    const sigsByTag = groupBy(sigs, (sig) => sig.data.keyTag)

    // Iterate over the DS records looking for keys we can verify
    const { algorithms, digests } = this.#prover
    for (const ds of dses) {
      for (const key of keysByTag.get(ds.data.keyTag) ?? []) {
        if (!this.checkDs(ds, key)) continue
        logger.info(
          `DS=${ds.data.keyTag}/${
            algorithms[ds.data.algorithm]?.name ?? ds.data.algorithm
          }/${digests[ds.data.digestType].name} verifies DNSKEY=${
            ds.data.keyTag
          }/${algorithms[key.data.algorithm]?.name ?? key.data.algorithm} on ${
            key.name
          }`,
        )
        for (const sig of sigsByTag.get(ds.data.keyTag) ?? []) {
          const ss = new SignedSet(keys, sig)
          if (this.verifySignature(ss, key)) {
            logger.info(
              `RRSIG=${sig.data.keyTag}/${
                algorithms[sig.data.algorithm].name
              } verifies the DNSKEY RRSET on ${keys[0].name}`,
            )
            return { answer: ss, proofs }
          }
        }
      }
    }

    logger.warn(
      `Could not find any DS records to verify the DNSKEY RRSET on ${keys[0].name}`,
    )
    throw new NoValidDsError(keys)
  }

  verifySignature<T extends RecordAnswer>(
    answer: SignedSet<T>,
    key: DnskeyAnswer,
  ): boolean {
    const keyTag = getKeyTag(key)
    const { data } = answer.signature
    if (
      key.data.algorithm !== data.algorithm ||
      keyTag !== data.keyTag ||
      key.name !== data.signersName
    ) {
      return false
    }
    const algorithm: SignatureAlgorithm | undefined =
      this.#prover.algorithms[key.data.algorithm]
    if (algorithm === undefined) {
      logger.warn(
        `Unrecognised signature algorithm for DNSKEY=${keyTag}/${key.data.algorithm} on ${key.name}`,
      )
      return false
    }
    return algorithm.f(key.data.key, answer.toWire(), data.signature)
  }

  checkDs(ds: DSAnswer, key: DnskeyAnswer): boolean {
    if (key.data.algorithm !== ds.data.algorithm || key.name !== ds.name) {
      return false
    }
    const data = concatBytes(encodeName(ds.name), encodeRdata(key))
    const digest: DigestAlgorithm | undefined =
      this.#prover.digests[ds.data.digestType]
    if (digest === undefined) {
      logger.warn(
        `Unrecognised digest type for DS=${ds.data.keyTag}/${
          ds.data.digestType
        }/${
          this.#prover.algorithms[ds.data.algorithm]?.name ?? ds.data.algorithm
        } on ${ds.name}`,
      )
      return false
    }
    return digest.f(data, ds.data.digest)
  }

  async dnsQuery(qtype: RecordType, qname: string): Promise<DnsResponse> {
    const query: Packet = {
      type: 'query',
      id: 1,
      flags: RECURSION_DESIRED,
      questions: [
        {
          type: qtype,
          class: 'IN',
          name: qname,
        },
      ],
      additionals: [
        {
          type: 'OPT',
          name: '.',
          udpPayloadSize: 4096,
          extendedRcode: 0,
          ednsVersion: 0,
          flags: DNSSEC_OK,
          flag_do: true,
          options: [],
        },
      ],
      answers: [],
    }
    const key = `${qname} ${qtype}`
    let response = this.#cache.get(key)
    if (response === undefined) {
      response = await this.#prover.sendQuery(query)
      this.#cache.set(key, response)
    }
    logger.info(
      `Query[${qname} ${qtype}]:\n${answersToString(response.answers ?? [])}`,
    )
    if (response.rcode !== 'NOERROR') {
      throw new ResponseCodeError(query, response)
    }
    return response
  }
}

export class DNSProver {
  sendQuery: (q: Packet) => Promise<DnsResponse>

  digests: Record<number, DigestAlgorithm>

  algorithms: Record<number, SignatureAlgorithm>

  anchors: DSAnswer[]

  static create(url: string) {
    return new DNSProver(dohQuery(url))
  }

  constructor(
    sendQuery: (q: Packet) => Promise<DnsResponse>,
    digests = DEFAULT_DIGESTS,
    algorithms = DEFAULT_ALGORITHMS,
    anchors = DEFAULT_TRUST_ANCHORS,
  ) {
    this.sendQuery = sendQuery
    this.digests = digests
    this.algorithms = algorithms
    this.anchors = anchors
  }

  async queryWithProof<T extends RecordType>(
    qtype: T,
    qname: string,
  ): Promise<ProvableAnswer<AnswerOf<T>> | null> {
    return new DNSQuery(this).queryWithProof(qtype, qname)
  }
}
