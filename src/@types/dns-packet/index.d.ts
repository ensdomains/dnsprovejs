declare module 'dns-packet' {
  const AUTHORITATIVE_ANSWER: number
  const TRUNCATED_RESPONSE: number
  const RECURSION_DESIRED: number
  const RECURSION_AVAILABLE: number
  const AUTHENTIC_DATA: number
  const CHECKING_DISABLED: number
  const DNSSEC_OK: number
	
  function decode(buf: Buffer, offset?: number): Packet
  function encode(packet: Packet, buf?: Buffer, offset?: number): Buffer
	
  interface Packet {
    id?: number
    type: 'query' | 'response'
    flags?: number
    rcode?: string
    questions: Question[]
    answers?: Answer[]
    authorities?: Answer[]
    additionals?: Answer[]
  }
	
  interface Question {
    type: string
    class: string
    name: string
  }

  interface AnswerBase {
    type: string
    class: string
    name: string
    ttl?: number
  }

  interface A extends AnswerBase {
    type: 'A'
    data: string
  }

  interface Dnskey extends AnswerBase {
    type: 'DNSKEY'
    data: {
      flags: number
      algorithm: number
      key: Buffer
    }
  }

  interface Ds extends AnswerBase {
    type: 'DS'
    data: {
      keyTag: number
      algorithm: number
      digestType: number
      digest: Buffer
    }
  }

  interface Opt extends AnswerBase {
    type: 'OPT'
    udpPayloadSize?: number
    extendedRcode?: number
    ednsVersion?: number
    flags?: number
    data?: any
  }

  interface Rrsig extends AnswerBase {
    type: 'RRSIG'
    data: {
      typeCovered: string
      algorithm: number
      labels: number
      originalTTL: number
      expiration: number
      inception: number
      keyTag: number
      signersName: string
      signature: Buffer
    }
  }

  interface Rtxt extends AnswerBase {
    type: 'TXT'
    data: Buffer[]
  }

  type Answer = A|Dnskey|Ds|Opt|Rrsig|Rtxt

  interface Encodable<T> {
    decode(buf: Buffer, offset?: number): T
    encode(packet: T, buf?: Buffer, offset?: number): Buffer
  }

  const answer: Encodable<Answer>
  const dnskey: Encodable<Dnskey['data']>
  const name: Encodable<string>
  const rrsig: Encodable<Rrsig['data']>
}
