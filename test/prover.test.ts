import * as assert from 'assert';

import { MockResolver } from './mock-resolver';
import { anchors, inigomontoyaXyzChain, toSignedRRset } from '.';

import { Prover } from '../src/prover';

for (const [name, rdtype, rrsets] of [
  ['_ens.inigomontoya.xyz', 'TXT', inigomontoyaXyzChain]
] as const) {
  it(name, async () => {
    const resolver = new MockResolver(rrsets);
    const [chain, proof] = await new Prover({
      resolver,
      anchors
    }).prove(name, rdtype);
    assert.deepStrictEqual(chain, rrsets.map(toSignedRRset).reverse());
    assert.deepStrictEqual(proof, anchors);
    const { done } = resolver.rrsets.next();
    assert.ok(done);
  });
}
