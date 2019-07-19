import * as assert from 'assert';
import * as crypto from 'crypto';

import * as wireFormat from 'dns-packet';

import { Algorithm } from './algorithms';
import {
  ECDSAAlgorithm,
  secp256r1,
  secp384r1
} from './algorithms/ecdsa-algorithm';
import { RSAAlgorithm } from './algorithms/rsa-algorithm';
import { RR, SignedRRset } from '.';

function decodeSignedData(signedData: Buffer): RR<'RRSIG'>['data'] {
  const buf = Buffer.alloc(2 + signedData.length);
  buf.writeUInt16BE(signedData.length, 0);
  buf.set(signedData, 2);
  return wireFormat.rrsig.decode(buf);
}

function* decodeRRs(rrs: Buffer): IterableIterator<RR> {
  for (let offset = 0; offset < rrs.length; ) {
    const rr = wireFormat.answer.decode(rrs, offset);
    offset += wireFormat.answer.decode.bytes;
    yield rr;
  }
}

export class BaseValidator {
  *validateRRset(
    { signedData }: SignedRRset,
    proof: Buffer | Iterable<RR>
  ): IterableIterator<assert.AssertionError> {
    const rrsigRdata = decodeSignedData(signedData);
    const rrs = decodeRRs(rrsigRdata.signature);
    if (proof instanceof Buffer) {
      proof = decodeRRs(proof);
    }
    for (const dnskey of rrsigRdata.typeCovered == 'DNSKEY' ? rrs : proof) {
      if (dnskey.type == 'DNSKEY') {
        if (rrsigRdata.typeCovered == 'DNSKEY') {
          const keyTags = [...proof]
            .filter(ds => ds.type == 'DS')
            .map(ds => ds.data.keyTag);
          if (!keyTags.includes(rrsigRdata.keyTag)) {
            yield new assert.AssertionError({
              actual: keyTags,
              expected: rrsigRdata.keyTag,
              operator: 'in'
            });
          }
        }
        return rrs;
      }
    }
    yield new assert.AssertionError({
      actual: 0,
      expected: 0,
      operator: '>'
    });
    return rrs;
  }

  *validate(
    chain: Iterable<SignedRRset>,
    proof: Buffer | Iterable<RR>
  ): IterableIterator<assert.AssertionError> {
    for (const signedRRset of chain) {
      proof = yield* this.validateRRset(signedRRset, proof);
    }
    return proof;
  }
}

// RFC 4034 Appendix B Key Tag Calculation
export function calculateKeyTag(dnskeyRdata: Buffer): number {
  let keyTag = 0;
  for (const [i, byte] of dnskeyRdata.entries()) {
    keyTag += i & 1 ? byte : byte << 8;
  }
  return (keyTag + (keyTag >>> 16)) & 0xffff;
}

interface Options {
  algorithms?: Record<number, Algorithm>;
  digests?: Record<number, string>;
}

export class Validator extends BaseValidator {
  algorithms: Record<number, Algorithm>;
  digests: Record<number, string>;

  constructor({
    // RFC 8624 Section 3.1 DNSKEY Algorithms
    algorithms = {
      5: new RSAAlgorithm('SHA1'),
      7: new RSAAlgorithm('SHA1'),
      8: new RSAAlgorithm('SHA256'),
      10: new RSAAlgorithm('SHA512'),
      13: new ECDSAAlgorithm(secp256r1, 'SHA256'),
      14: new ECDSAAlgorithm(secp384r1, 'SHA384')
    },
    // RFC 8624 Section 3.3 DS and CDS Algorithms
    digests = {
      1: 'SHA1',
      2: 'SHA256',
      4: 'SHA384'
    }
  }: Options = {}) {
    super();
    this.algorithms = algorithms;
    this.digests = digests;
  }

  *validateRRset(
    { signedData, signature }: SignedRRset,
    proof: Buffer | Iterable<RR>
  ): IterableIterator<assert.AssertionError> {
    const rrsigRdata = decodeSignedData(signedData);
    const rrs = [...decodeRRs(rrsigRdata.signature)];
    if (proof instanceof Buffer) {
      proof = decodeRRs(proof);
    }
    // The RRSIG RR and the RRset MUST have the same owner name and the
    // same class
    const [first, ...rest] = rrs;
    for (const rr of rest) {
      if (rr.name != first.name) {
        yield new assert.AssertionError({
          actual: rr.name,
          expected: first.name,
          operator: '=='
        });
      }
      if (rr.class != first.class) {
        yield new assert.AssertionError({
          actual: rr.class,
          expected: first.class,
          operator: '=='
        });
      }
    }
    for (const rr of rrs) {
      // The RRSIG RR's Type Covered field MUST equal the RRset's type
      if (rr.type != rrsigRdata.typeCovered) {
        yield new assert.AssertionError({
          actual: rr.type,
          expected: rrsigRdata.typeCovered,
          operator: '=='
        });
      }
      // The number of labels in the RRset owner name MUST be greater
      // than or equal to the value in the RRSIG RR's Labels field
      if ((rr.name != '.' && rr.name.split('.').length) < rrsigRdata.labels) {
        yield new assert.AssertionError({
          actual: rr.name,
          expected: rrsigRdata.labels,
          operator: '>='
        });
      }
    }
    // The validator's notion of the current time MUST be less than or
    // equal to the time listed in the RRSIG RR's Expiration field
    if ((rrsigRdata.expiration - Date.now() / 1000) >> 0 < 0) {
      yield new assert.AssertionError({
        actual: rrsigRdata.expiration,
        expected: Date.now() / 1000,
        operator: '<='
      });
    }
    // The validator's notion of the current time MUST be greater than
    // or equal to the time listed in the RRSIG RR's Inception field
    if ((Date.now() / 1000 - rrsigRdata.inception) >> 0 < 0) {
      yield new assert.AssertionError({
        actual: rrsigRdata.expiration,
        expected: Date.now() / 1000,
        operator: '>='
      });
    }
    const result = [];
    for (const dnskey of rrsigRdata.typeCovered == 'DNSKEY' ? rrs : proof) {
      if (dnskey.type == 'DNSKEY') {
        // The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields
        // MUST match the owner name, algorithm, and key tag for some
        // DNSKEY RR in the zone's apex DNSKEY RRset
        if (dnskey.name != rrsigRdata.signersName) {
          result.push(
            new assert.AssertionError({
              actual: dnskey.name,
              expected: rrsigRdata.signersName,
              operator: '=='
            })
          );
          // The matching DNSKEY RR MUST be present in the zone's apex
          // DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA
          // Flag bit 7) set
        } else if (~dnskey.data.flags & 256) {
          result.push(
            new assert.AssertionError({
              actual: dnskey.data.flags,
              expected: 256,
              operator: '&'
            })
          );
        } else if (dnskey.data.algorithm != rrsigRdata.algorithm) {
          result.push(
            new assert.AssertionError({
              actual: dnskey.data.algorithm,
              expected: rrsigRdata.algorithm,
              operator: '=='
            })
          );
        } else {
          const dnskeyRdata = wireFormat.dnskey.encode(dnskey.data).slice(2);
          const keyTag = calculateKeyTag(dnskeyRdata);
          if (keyTag != rrsigRdata.keyTag) {
            result.push(
              new assert.AssertionError({
                actual: keyTag,
                expected: rrsigRdata.keyTag,
                operator: '=='
              })
            );
          } else {
            const algorithm = this.algorithms[rrsigRdata.algorithm];
            if (algorithm === undefined) {
              result.push(
                new assert.AssertionError({
                  actual: rrsigRdata.algorithm,
                  expected: Object.keys(this.algorithms),
                  operator: 'in'
                })
              );
            } else if (
              !algorithm.verify(
                {
                  signedData,
                  signature
                },
                dnskey.data.key
              )
            ) {
              result.push(
                new assert.AssertionError({
                  actual: false,
                  expected: true,
                  operator: '=='
                })
              );
            } else if (rrsigRdata.typeCovered == 'DNSKEY') {
              for (const ds of proof) {
                if (ds.type == 'DS') {
                  // The Algorithm and Key Tag in the DS RR match the
                  // Algorithm field and the key tag of a DNSKEY RR in
                  // the child zone's apex DNSKEY RRset, and, when the
                  // DNSKEY RR's owner name and RDATA are hashed using
                  // the digest algorithm specified in the DS RR's
                  // Digest Type field, the resulting digest value
                  // matches the Digest field of the DS RR
                  if (ds.data.keyTag != keyTag) {
                    result.push(
                      new assert.AssertionError({
                        actual: ds.data.keyTag,
                        expected: rrsigRdata.keyTag,
                        operator: '=='
                      })
                    );
                  } else if (ds.data.algorithm != dnskey.data.algorithm) {
                    result.push(
                      new assert.AssertionError({
                        actual: ds.data.algorithm,
                        expected: dnskey.data.algorithm,
                        operator: '=='
                      })
                    );
                  } else {
                    const digestType = this.digests[ds.data.digestType];
                    if (digestType === undefined) {
                      result.push(
                        new assert.AssertionError({
                          actual: ds.data.digestType,
                          expected: Object.keys(this.digests),
                          operator: 'in'
                        })
                      );
                    } else {
                      const digest = crypto
                        .createHash(digestType)
                        .update(
                          Buffer.concat([
                            wireFormat.name.encode(dnskey.name),
                            dnskeyRdata
                          ])
                        )
                        .digest();
                      if (!ds.data.digest.equals(digest)) {
                        result.push(
                          new assert.AssertionError({
                            actual: ds.data.digest,
                            expected: digest,
                            operator: '=='
                          })
                        );
                      } else {
                        return rrs;
                      }
                    }
                  }
                }
              }
            } else {
              return rrs;
            }
          }
        }
      }
    }
    if (!result.length) {
      yield new assert.AssertionError({
        actual: 0,
        expected: 0,
        operator: '>'
      });
    } else {
      yield* result;
    }
    return rrs;
  }
}
