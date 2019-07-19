import * as crypto from 'crypto';

import * as asn1 from 'parse-asn1/asn1';

import { Algorithm } from '.';
import { SignedRRset } from '..';

// RFC 8017 Appendix A.1 RSA Key Representation
const algorithm = [1, 2, 840, 113549, 1, 1, 1] as const;

export class RSAAlgorithm implements Algorithm {
  digestType: string;

  constructor(digestType: string) {
    this.digestType = digestType;
  }

  createPublicKey(publicKey: Buffer): string {
    // RFC 3110 Section 2 RSA Public KEY Resource Records
    let [exponentLength] = publicKey,
      publicExponent,
      modulus;
    if (exponentLength) {
      publicExponent = publicKey.slice(1, 1 + exponentLength);
      modulus = publicKey.slice(1 + exponentLength);
    } else {
      exponentLength = publicKey.readUInt16BE(1);
      publicExponent = publicKey.slice(3, 3 + exponentLength);
      modulus = publicKey.slice(3 + exponentLength);
    }
    // RFC 8017 Appendix A.1.1 RSA Public Key Syntax
    const data = asn1.RSAPublicKey.encode({
      modulus,
      publicExponent
    });
    return asn1.PublicKey.encode(
      {
        algorithm: { algorithm },
        subjectPublicKey: { data }
      },
      'pem',
      {
        label: 'PUBLIC KEY'
      }
    );
  }

  verify({ signedData, signature }: SignedRRset, publicKey: Buffer): boolean {
    return crypto
      .createVerify(this.digestType)
      .update(signedData)
      .verify(this.createPublicKey(publicKey), signature);
  }
}
