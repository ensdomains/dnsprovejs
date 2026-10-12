export type {
  DigestAlgorithm,
  DnsResponse,
  ProvableAnswer,
  RecordAnswer,
  SignatureAlgorithm,
} from './prove.js'
export {
  DEFAULT_ALGORITHMS,
  DEFAULT_DIGESTS,
  DEFAULT_TRUST_ANCHORS,
  DNSProver,
  dohQuery,
  NoValidDnskeyError,
  NoValidDsError,
  ResponseCodeError,
  SignedSet,
} from './prove.js'
