import * as assert from 'assert';

import * as wireFormat from 'dns-packet';

import { RSAAlgorithm } from '../../src/algorithms/rsa-algorithm';

const rrs = wireFormat.answer.encode({
  name: 'www.example.net',
  type: 'A',
  ttl: 3600,
  data: '192.0.2.91'
});

it('RFC 5702 Section 6.1 RSA/SHA-256 Key and Signature', () => {
  const rrsigRdata = wireFormat.rrsig
    .encode({
      typeCovered: 'A',
      algorithm: 8,
      labels: 3,
      originalTTL: 3600,
      expiration: 1893456000,
      inception: 946684800,
      keyTag: 9033,
      signersName: 'example.net',
      signature: Buffer.alloc(0)
    })
    .slice(2);
  const signedData = Buffer.concat([rrsigRdata, rrs]);
  const signature = Buffer.from(
    'kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==',
    'base64'
  );
  const publicKey = Buffer.from(
    'AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=',
    'base64'
  );
  assert.ok(
    new RSAAlgorithm('SHA256').verify(
      {
        signedData,
        signature
      },
      publicKey
    )
  );
});

it('RFC 5702 Section 6.2 RSA/SHA-512 Key and Signature', () => {
  const rrsigRdata = wireFormat.rrsig
    .encode({
      typeCovered: 'A',
      algorithm: 10,
      labels: 3,
      originalTTL: 3600,
      expiration: 1893456000,
      inception: 946684800,
      keyTag: 3740,
      signersName: 'example.net',
      signature: Buffer.alloc(0)
    })
    .slice(2);
  const signedData = Buffer.concat([rrsigRdata, rrs]);
  const signature = Buffer.from(
    'tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=',
    'base64'
  );
  const publicKey = Buffer.from(
    'AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL',
    'base64'
  );
  assert.ok(
    new RSAAlgorithm('SHA512').verify(
      {
        signedData,
        signature
      },
      publicKey
    )
  );
});
