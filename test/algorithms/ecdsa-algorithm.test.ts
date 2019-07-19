import * as assert from 'assert';

import * as wireFormat from 'dns-packet';

import {
  ECDSAAlgorithm,
  secp256r1,
  secp384r1
} from '../../src/algorithms/ecdsa-algorithm';

const rrs = wireFormat.answer.encode({
  name: 'www.example.net',
  type: 'A',
  ttl: 3600,
  data: '192.0.2.1'
});

it('RFC 6605 Section 6.1 P-256 Example', () => {
  const rrsigRdata = wireFormat.rrsig
    .encode({
      typeCovered: 'A',
      algorithm: 13,
      labels: 3,
      originalTTL: 3600,
      expiration: 1284026679,
      inception: 1281607479,
      keyTag: 55648,
      signersName: 'example.net',
      signature: Buffer.alloc(0)
    })
    .slice(2);
  const signedData = Buffer.concat([rrsigRdata, rrs]);
  const signature = Buffer.from(
    'qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==',
    'base64'
  );
  const publicKey = Buffer.from(
    'GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==',
    'base64'
  );
  assert.ok(
    new ECDSAAlgorithm(secp256r1, 'SHA256').verify(
      {
        signedData,
        signature
      },
      publicKey
    )
  );
});

it('RFC 6605 Section 6.2 P-384 Example', () => {
  const rrsigRdata = wireFormat.rrsig
    .encode({
      typeCovered: 'A',
      algorithm: 14,
      labels: 3,
      originalTTL: 3600,
      expiration: 1284027625,
      inception: 1281608425,
      keyTag: 10771,
      signersName: 'example.net',
      signature: Buffer.alloc(0)
    })
    .slice(2);
  const signedData = Buffer.concat([rrsigRdata, rrs]);
  const signature = Buffer.from(
    '/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm',
    'base64'
  );
  const publicKey = Buffer.from(
    'xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40',
    'base64'
  );
  assert.ok(
    new ECDSAAlgorithm(secp384r1, 'SHA384').verify(
      {
        signedData,
        signature
      },
      publicKey
    )
  );
});
