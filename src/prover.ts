import * as types from 'dns-packet/types';
import * as web3Utils from 'web3-utils';
import * as wireFormat from 'dns-packet';

import { BaseValidator } from './validator';
import { DNSResolver } from './resolvers/dns-resolver';
import { DoHResolver } from './resolvers/doh-resolver';
import { Oracle, OracleResult } from './oracle';
import { Resolver, Response } from './resolvers';
import { SignedRRset } from '.';

// https://data.iana.org/root-anchors/root-anchors.xml
export const rootAnchors = wireFormat.answer.encode({
  name: '.',
  type: 'DS',
  data: {
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: Buffer.from(
      'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d',
      'hex'
    )
  }
});

interface Options {
  resolver?: Resolver;
  oracle?: Oracle;
  anchors?: Buffer;
  validator?: BaseValidator;
}

export class Prover {
  resolver: Resolver;
  oracle?: Oracle;
  anchors: Buffer;
  validator: BaseValidator;

  constructor({
    resolver = (process as any).browser ? new DoHResolver() : new DNSResolver(),
    oracle,
    anchors = oracle === undefined ? rootAnchors : oracle.anchors(),
    validator = new BaseValidator()
  }: Options = {}) {
    this.resolver = resolver;
    this.oracle = oracle;
    this.anchors = anchors;
    this.validator = validator;
  }

  async prove(
    name: string,
    rdtype: string | number,
    validateRRset?: SignedRRset
  ): Promise<[SignedRRset[], Buffer]> {
    if (typeof rdtype != 'string') {
      rdtype = types.toString(rdtype);
    }
    // https://github.com/microsoft/TypeScript/pull/33055
    const [{ answers }, { hash, inserted }] = await Promise.all([
      this.resolver.lookup(name, rdtype),
      this.oracle !== undefined && this.oracle.lookup(name, rdtype)
    ] as [Promise<Response>, Promise<OracleResult>]);
    let err;
    if (validateRRset !== undefined) {
      [err] = this.validator.validateRRset(
        validateRRset,
        answers.filter(rr => rr.type == rdtype)
      );
      if (err) {
        throw err;
      }
    }
    for (const rrsig of answers) {
      if (rrsig.type == 'RRSIG') {
        // RFC 4035 Section 5.3.2 Reconstructing the Signed Data
        const rrs = Buffer.concat(
          answers
            .filter(rr => rr.type == rdtype)
            .map(rr =>
              wireFormat.answer.encode({
                ...rr,
                ttl: rrsig.data.originalTTL
              })
            )
            // RFC 4034 Section 6.3 Canonical RR Ordering within an
            // RRset
            .sort((a, b) => a.compare(b))
        );
        if (
          web3Utils.keccak256(rrs).slice(0, 2 + 40) == hash &&
          Date.now() / 1000 - inserted <= rrsig.data.originalTTL
        ) {
          return [[], rrs];
        } else {
          const rrsigRdata = wireFormat.rrsig
            .encode({
              ...rrsig.data,
              signature: Buffer.alloc(0)
            })
            .slice(2);
          const signedRRset = {
            signedData: Buffer.concat([rrsigRdata, rrs]),
            signature: rrsig.data.signature
          };
          [err] = this.validator.validateRRset(signedRRset, this.anchors);
          if (!err) {
            return [[signedRRset], this.anchors];
          }
          const [chain, proof] =
            rdtype == 'DNSKEY'
              ? await this.prove(name, 'DS', signedRRset)
              : await this.prove(rrsig.data.signersName, 'DNSKEY', signedRRset);
          chain.push(signedRRset);
          return [chain, proof];
        }
      }
    }
    throw err;
  }
}
