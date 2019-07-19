export * from './algorithms';
export * from './oracle';
export * from './prover';
export * from './resolvers';
export * from './validator';

export interface SignedRRset {
  signedData: Buffer;
  signature: Buffer;
}

interface BaseRR<T> {
  name: string;
  type: T;
  class?: string | number;
  data: any;
}

interface RRSIG extends BaseRR<'RRSIG'> {
  data: {
    typeCovered: string | number;
    algorithm: number;
    labels: number;
    originalTTL: number;
    expiration: number;
    inception: number;
    keyTag: number;
    signersName: string;
    signature: Buffer;
  };
}

interface DNSKEY extends BaseRR<'DNSKEY'> {
  data: {
    flags: number;
    algorithm: number;
    key: Buffer;
  };
}

interface DS extends BaseRR<'DS'> {
  data: {
    keyTag: number;
    algorithm: number;
    digestType: number;
    digest: Buffer;
  };
}

type TypedRR = RRSIG | DNSKEY | DS;

export type RR<T = string | number> = T extends TypedRR['type']
  ? Extract<TypedRR, { type: T }>
  : BaseRR<T>;
