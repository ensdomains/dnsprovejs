import * as wireFormat from 'dns-packet';

import { RR, SignedRRset } from '../src';

export type RRset<T = string | number> = readonly [
  string, // name
  T, // rdtype
  readonly RR<T>['data'][], // rds
  number, // keyTag
  string, // signersName
  Buffer // signature
];

export const algorithm = 13; // ECDSAP256SHA256
export const digestType = 2; // SHA256

const inigomontoyaXyzZskPublicKey = Buffer.from(
  'LY2NS+coUBPPBesoBWahyqTxpBOmMYNBiBEordgoKj+HveDIk5QFCs+q/Fm+2M2iMOTIu8yIgcSPbNn7u11wnA==',
  'base64'
);
const inigomontoyaXyzZskKeyTag = 46101;
const inigomontoyaXyzKskPublicKey = Buffer.from(
  'jFaMRppDTiCOntOju99WLr4xC/7eT9NZMlGphUDQZeUKB3wZzVFxDHhE8Rlq0LaggZpq22jvBqeZje2A0K2fOQ==',
  'base64'
);
const inigomontoyaXyzKskKeyTag = 6678;
const inigomontoyaXyzDigest = Buffer.from(
  '090f07f8153aa059483da6e9487a910a73e78c76a37024c94e4195bf6cb604a2',
  'hex'
);
const xyzZskPublicKey = Buffer.from(
  't4UDYbad9XSKXRjWvrQ5WfIxcM5hNob5QLcjhIHVxfo0QxEN1qxlC/mVjpcTG6dU/uaXlFtPjSUNA5HOf3gdyg==',
  'base64'
);
const xyzZskKeyTag = 31790;
const xyzKskPublicKey = Buffer.from(
  '1MvfZUUuEQOXztomy53lUhl0jCpL6fQW6WcnCg56v3EnfnsuAfn6L0ZKoL5s08eh7AFTRI7FcZhgzPQ0nqmpgg==',
  'base64'
);
const xyzKskKeyTag = 35961;
const xyzDigest = Buffer.from(
  '897d708f5b05711ff44a7993fa84081976300c2ed2c0f80a08d40b011fa46d94',
  'hex'
);
const zskPublicKey = Buffer.from(
  '6UzA3QSr2/H+h4Q8ivSR161dsFHqosh6TI37eVFxDyjPw6gvgTXYYn7Qv5YjuK/B6vNpfa3DgxHhAblTwap9Mg==',
  'base64'
);
const zskKeyTag = 10681;
const kskPublicKey = Buffer.from(
  'MQMSyHJns6r8b8ZdR1Q9k5e3Z3TseTEe/YU5Z0/WY/IeY0A7R7KKJemuUjfp0KDQLIZLFGgatSdOEDbiV+d9AA==',
  'base64'
);
const kskKeyTag = 41679;
const digest = Buffer.from(
  'c9ecdcf48c64b0cbf1ffb0e6a193c89c9541613401c07ddf7ff489ef12d4ee6f',
  'hex'
);

const _ensInigomontoyaXyz = [
  '_ens.inigomontoya.xyz',
  'TXT',
  ['a=0x9cce34F7aB185c7ABA1b7C8140d620B4BDA941d6'],
  inigomontoyaXyzZskKeyTag,
  'inigomontoya.xyz',
  Buffer.from(
    '1Xa8AQ6p1QEXGtqDuJwMNHIB7P6kRvDMyvlcm0LTi/IGBBQChh9xFiN9JHkPTMOcXPt4dldVcnBnNlJ2+Y0gbg==',
    'base64'
  )
] as const;
const inigomontoyaXyzDnskey = [
  'inigomontoya.xyz',
  'DNSKEY',
  [
    {
      flags: 256,
      algorithm,
      key: inigomontoyaXyzZskPublicKey
    },
    {
      flags: 257,
      algorithm,
      key: inigomontoyaXyzKskPublicKey
    }
  ],
  inigomontoyaXyzKskKeyTag,
  'inigomontoya.xyz',
  Buffer.from(
    'Yzy3h0GLa8hAKMCAmO0/j4pGLVtgwwO4LAzYWpcT0ii4Cdfi8lxJVpusnief8X45jLfshIyZQ1H/6aDL2C8hqw==',
    'base64'
  )
] as const;
const inigomontoyaXyzDs = [
  'inigomontoya.xyz',
  'DS',
  [
    {
      keyTag: inigomontoyaXyzKskKeyTag,
      algorithm,
      digestType,
      digest: inigomontoyaXyzDigest
    }
  ],
  xyzZskKeyTag,
  'xyz',
  Buffer.from(
    'ObX7znhKgdtY2sMd6RbbhOLpwXFTHOzH9W8fFsRDmHfOrquMA+20fmW3ffZMOZ9ND1mDyv5MAV3SzP3Z+6xt4A==',
    'base64'
  )
] as const;
const xyzDnskey = [
  'xyz',
  'DNSKEY',
  [
    {
      flags: 256,
      algorithm,
      key: xyzZskPublicKey
    },
    {
      flags: 257,
      algorithm,
      key: xyzKskPublicKey
    }
  ],
  xyzKskKeyTag,
  'xyz',
  Buffer.from(
    '/wVmjUDGAXOcLyyWBXl09c+aVS606Y5a/OvnNflTqCBjAuOYrKv5J9Gqc7mihPRirMcDDxrJKGu/0JSSfr1fBg==',
    'base64'
  )
] as const;
const xyzDs = [
  'xyz',
  'DS',
  [
    {
      keyTag: xyzKskKeyTag,
      algorithm,
      digestType,
      digest: xyzDigest
    }
  ],
  zskKeyTag,
  '.',
  Buffer.from(
    'CaC5n68qnGHV050Uk2rcEkWiv9Q5vsrdaE1UQu638alX/QK1y2g4XFO6YDsbrcZ8TQSOlkp6aPNQ9x7GpfWK+A==',
    'base64'
  )
] as const;
const dnskey = [
  '.',
  'DNSKEY',
  [
    {
      flags: 256,
      algorithm,
      key: zskPublicKey
    },
    {
      flags: 257,
      algorithm,
      key: kskPublicKey
    }
  ],
  kskKeyTag,
  '.',
  Buffer.from(
    'EkXxFSTGWhbWpiiGMzEr77wqmJ1PsdztdF3Q4ldIuBEtr5erQglDb/Ncx046sPchs6FBfGFOOlKzJdH8Vh8GCg==',
    'base64'
  )
] as const;

export const anchors = wireFormat.answer.encode({
  name: '.',
  type: 'DS',
  data: {
    keyTag: kskKeyTag,
    algorithm,
    digestType,
    digest
  }
});

export const inigomontoyaXyzChain = [
  _ensInigomontoyaXyz,
  inigomontoyaXyzDnskey,
  inigomontoyaXyzDs,
  xyzDnskey,
  xyzDs,
  dnskey
] as const;

export function toRRs<T>([name, rdtype, rds]: readonly [
  string,
  T,
  readonly RR<T>['data'][]
]): RR<T>[] {
  return rds.map(
    rdata =>
      // https://github.com/microsoft/TypeScript/issues/33014
      ({
        name,
        // https://github.com/microsoft/TypeScript/pull/30779
        // https://github.com/microsoft/TypeScript/issues/32399
        type: rdtype,
        data: rdata
      } as any)
  );
}

export function toSignedRRset([
  name,
  rdtype,
  rds,
  keyTag,
  signersName,
  signature
]: RRset): SignedRRset {
  const rrs = Buffer.concat(
    toRRs([name, rdtype, rds]).map(rr => wireFormat.answer.encode(rr))
  );
  const rrsigRdata = wireFormat.rrsig
    .encode({
      typeCovered: rdtype,
      algorithm,
      labels: name != '.' && name.split('.').length,
      signersName,
      keyTag,
      signature: Buffer.alloc(0)
    })
    .slice(2);
  return {
    signedData: Buffer.concat([rrsigRdata, rrs]),
    signature
  };
}
