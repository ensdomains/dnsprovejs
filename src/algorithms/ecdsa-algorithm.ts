import * as crypto from 'crypto';

import * as asn1 from 'asn1.js';

import { Algorithm } from '.';
import { SignedRRset } from '..';

// RFC 5480 Section 2.1.1 Unrestricted Algorithm Identifier and
// Parameters
const algorithm = [1, 2, 840, 10045, 2, 1] as const;

// RFC 5480 Section 2.1.1.1 Named Curve
export const secp256r1 = [1, 2, 840, 10045, 3, 1, 7] as const;
export const secp384r1 = [1, 3, 132, 0, 34] as const;

// https://github.com/indutny/asn1.js/issues/112

// RFC 5480 Section 2 Subject Public Key Information Fields
const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function(
  this: any
) {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters')
      .any()
      .optional()
  );
});
const SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function(
  this: any
) {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('subjectPublicKey').bitstr()
  );
});

// RFC 5480 Section 2.1.1 Unrestricted Algorithm Identifier and
// Parameters
const ECParameters = asn1.define('ECParameters', function(this: any) {
  this.choice({
    namedCurve: this.objid()
  });
});

// RFC 5480 Appendix A ASN.1 Module
const ECDSASigValue = asn1.define('ECDSA-Sig-Value', function(this: any) {
  this.seq().obj(this.key('r').int(), this.key('s').int());
});

// https://github.com/nodejs/node/issues/21662#issuecomment-486500805
function bigUint(buf: Buffer): bigint {
  // https://github.com/microsoft/TypeScript/pull/33139
  return (Array.prototype.map.call(buf, BigInt) as bigint[]).reduce(
    (result, byte) => (result << 8n) + byte
  );
}

// https://github.com/indutny/asn1.js/pull/113
function* encodeInteger(value: bigint): IterableIterator<number> {
  for (; BigInt.asIntN(8, value) != value; value >>= 8n) {
    yield Number(BigInt.asUintN(8, value));
  }
  yield Number(BigInt.asUintN(8, value));
}

export class ECDSAAlgorithm implements Algorithm {
  namedCurve: readonly number[];
  digestType: string;

  constructor(namedCurve: readonly number[], digestType: string) {
    this.namedCurve = namedCurve;
    this.digestType = digestType;
  }

  createPublicKey(publicKey: Buffer): string {
    // RFC 6605 Section 4 DNSKEY and RRSIG Resource Records for ECDSA,
    // RFC 5480 Section 2.2 Subject Public Key
    const data = Buffer.alloc(1 + publicKey.length);
    data[0] = 4;
    data.set(publicKey, 1);
    return SubjectPublicKeyInfo.encode(
      {
        algorithm: {
          algorithm,
          parameters: ECParameters.encode({
            type: 'namedCurve',
            value: this.namedCurve
          })
        },
        subjectPublicKey: { data }
      },
      'pem',
      {
        label: 'PUBLIC KEY'
      }
    );
  }

  verify({ signedData, signature }: SignedRRset, publicKey: Buffer): boolean {
    // RFC 6605 Section 4 DNSKEY and RRSIG Resource Records for ECDSA
    const r = Buffer.from(
      [
        ...encodeInteger(bigUint(signature.slice(0, signature.length / 2)))
      ].reverse()
    );
    const s = Buffer.from(
      [
        ...encodeInteger(bigUint(signature.slice(signature.length / 2)))
      ].reverse()
    );
    return crypto
      .createVerify(this.digestType)
      .update(signedData)
      .verify(this.createPublicKey(publicKey), ECDSASigValue.encode({ r, s }));
  }
}
