export {
  DEFAULT_ALGORITHMS,
  DEFAULT_DIGESTS,
  DEFAULT_TRUST_ANCHORS,
  dohQuery,
  DNSProver,
  NoValidDsError,
  NoValidDnskeyError,
  ResponseCodeError,
  SignedSet,
} from './prove.js'
export type {
  DigestAlgorithm,
  DnsResponse,
  ProvableAnswer,
  RecordAnswer,
  SignatureAlgorithm,
} from './prove.js'
