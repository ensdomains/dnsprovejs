import * as assert from 'assert';

import { Resolver, Response } from '../src/resolvers';
import { RRset, algorithm, toRRs } from '.';

export class MockResolver implements Resolver {
  rrsets: Iterator<RRset>;

  constructor(rrsets: Iterable<RRset>) {
    this.rrsets = rrsets[Symbol.iterator]();
  }

  async lookup(name: string, rdtype: string | number): Promise<Response> {
    const { done, value } = this.rrsets.next();
    assert.ok(!done);
    // https://github.com/microsoft/TypeScript/issues/8655#issuecomment-412685082
    const [
      expectedName,
      expectedRdtype,
      rds,
      keyTag,
      signersName,
      signature
    ] = value as RRset;
    assert.deepStrictEqual([name, rdtype], [expectedName, expectedRdtype]);
    return {
      answers: [
        ...toRRs([name, rdtype, rds]),
        {
          name,
          type: 'RRSIG',
          data: {
            typeCovered: rdtype,
            algorithm,
            labels: name != '.' && name.split('.').length,
            signersName,
            keyTag,
            signature
          }
        }
      ]
    };
  }
}
