import * as assert from 'assert';

import { anchors, inigomontoyaXyzChain, toSignedRRset } from '.';

import { Validator } from '../src/validator';

for (const rrsets of [inigomontoyaXyzChain] as const) {
  it('', async () => {
    Date.now = () => 0;
    assert.deepStrictEqual(
      [
        ...new Validator().validate(
          rrsets.map(toSignedRRset).reverse(),
          anchors
        )
      ],
      []
    );
  });
}
