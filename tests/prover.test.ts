import * as packet from 'dns-packet'
import { expect, it, describe } from 'bun:test'
import { keccak_256 } from '@noble/hashes/sha3'
import {
  DNSProver,
  DEFAULT_ALGORITHMS,
  DEFAULT_DIGESTS,
  DEFAULT_TRUST_ANCHORS,
  getKeyTag,
  SignedSet,
} from '../src/prove'

let randomdata = Uint8Array.of()
function makeKey(name: string): packet.Dnskey {
  randomdata = keccak_256(randomdata)
  return {
    name,
    type: 'DNSKEY',
    data: {
      flags: 256, // ZSK
      algorithm: 253,
      key: Buffer.from(randomdata),
    },
  }
}

function makeDs(signedKey: packet.Dnskey): packet.Ds {
  randomdata = keccak_256(randomdata)
  return {
    name: signedKey.name,
    type: 'DS',
    data: {
      keyTag: getKeyTag(signedKey),
      algorithm: signedKey.data.algorithm,
      digestType: 253,
      digest: Buffer.from(randomdata),
    },
  }
}

function makeProver(
  responses: { [qname: string]: { [qtype: string]: packet.Packet } },
  rootKey: packet.Dnskey,
) {
  const sendQuery = function (q: packet.Packet): Promise<packet.Packet> {
    if (q.questions.length !== 1) {
      throw new Error('Queries must have exactly one question')
    }
    const question = q.questions[0]
    const response = responses[question.name]?.[question.type]
    if (response === undefined) {
      throw new Error(`Unexpected query for ${question.name} ${question.type}`)
    }
    return Promise.resolve(
      Object.assign(response, { questions: q.questions, id: q.id }),
    )
  }
  const digests = Object.assign(DEFAULT_DIGESTS, {
    253: {
      name: 'DUMMY',
      f: () => true,
    },
  })
  const algorithms = Object.assign(DEFAULT_ALGORITHMS, {
    253: {
      name: 'DUMMY',
      f: () => true,
    },
  })
  const anchors = DEFAULT_TRUST_ANCHORS.slice()
  anchors.push(makeDs(rootKey))
  return new DNSProver(sendQuery, digests, algorithms, anchors)
}

function makeSignedResponse(
  answers: packet.Answer[],
  keys: packet.Dnskey[],
): packet.Packet {
  const a = answers.map((ans) => Object.assign(ans, { class: 'IN', ttl: 3600 }))
  const now = Math.floor(Date.now() / 1000)
  for (const key of keys) {
    a.push({
      name: a[0].name,
      type: 'RRSIG',
      class: 'IN',
      ttl: 3600,
      data: {
        typeCovered: a[0].type,
        algorithm: key.data.algorithm,
        labels: a[0].name.split('.').length - 1,
        originalTTL: a[0].ttl || 3600,
        expiration: now + 3600,
        inception: now - 3600,
        keyTag: getKeyTag(key),
        signersName: key.name,
        signature: Buffer.from(a[0].name),
      },
    })
  }
  return {
    type: 'response',
    rcode: 'NOERROR',
    answers: a,
    questions: [],
  }
}

function makeDsResponse(
  signedKey: packet.Dnskey,
  signingKeys: packet.Dnskey[],
): packet.Packet {
  return makeSignedResponse([makeDs(signedKey)], signingKeys)
}

describe('dnsprovejs', () => {
  it('correctly constructs a set of proofs', async () => {
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    const testKey = makeKey('test.tld.')
    const prover = makeProver(
      {
        'test.tld.': {
          TXT: makeSignedResponse(
            [
              {
                name: 'test.tld.',
                type: 'TXT',
                data: [Buffer.from('Hello, world!')],
              },
            ],
            [testKey],
          ),
          DNSKEY: makeSignedResponse([testKey], [testKey]),
          DS: makeDsResponse(testKey, [tldKey]),
        },
        'tld.': {
          DNSKEY: makeSignedResponse([tldKey], [tldKey]),
          DS: makeDsResponse(tldKey, [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )
    const result = await prover.queryWithProof('TXT', 'test.tld.')

    expect(result.answer).toMatchObject({
      records: [
        {
          name: 'test.tld.',
          type: 'TXT',
          data: [Buffer.from('Hello, world!')],
        },
      ],
      signature: {
        name: 'test.tld.',
        type: 'RRSIG',
        data: {
          signersName: 'test.tld.',
          typeCovered: 'TXT',
          labels: 2,
          keyTag: getKeyTag(testKey),
        },
      },
    })

    expect(result.proofs[0]).toMatchObject({
      records: [{ name: '.', type: 'DNSKEY' }],
      signature: {
        name: '.',
        data: {
          signersName: '.',
          keyTag: getKeyTag(rootKey),
        },
      },
    })
    expect(result.proofs[1]).toMatchObject({
      records: [
        { name: 'tld.', type: 'DS', data: { keyTag: getKeyTag(tldKey) } },
      ],
      signature: {
        name: 'tld.',
        data: {
          signersName: '.',
          keyTag: getKeyTag(rootKey),
        },
      },
    })
    expect(result.proofs[2]).toMatchObject({
      records: [{ name: 'tld.', type: 'DNSKEY' }],
      signature: {
        name: 'tld.',
        data: {
          signersName: 'tld.',
          keyTag: getKeyTag(tldKey),
        },
      },
    })
    expect(result.proofs[3]).toMatchObject({
      records: [
        { name: 'test.tld.', type: 'DS', data: { keyTag: getKeyTag(testKey) } },
      ],
      signature: {
        name: 'test.tld.',
        data: {
          signersName: 'tld.',
          keyTag: getKeyTag(tldKey),
        },
      },
    })
    expect(result.proofs[4]).toMatchObject({
      records: [
        {
          name: 'test.tld.',
          type: 'DNSKEY',
        },
      ],
      signature: {
        name: 'test.tld.',
        data: {
          signersName: 'test.tld.',
          keyTag: getKeyTag(testKey),
        },
      },
    })
  })

  it('ignores RRSIGs with unknown algorithms', async () => {
    const rootKey = makeKey('.')
    const alternateRootKey = makeKey('.')
    alternateRootKey.data.algorithm = 252

    const prover = makeProver(
      {
        '.': {
          DNSKEY: makeSignedResponse(
            [alternateRootKey, rootKey],
            [alternateRootKey, rootKey],
          ),
        },
      },
      rootKey,
    )
    const result = await prover.queryWithProof('DNSKEY', '.')

    expect(result).toMatchObject({
      answer: {
        signature: {
          data: {
            algorithm: 253,
          },
        },
        records: { length: 2 },
      },
      proofs: [],
    })
  })

  it('ignores DSes with unknown digest types', async () => {
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    const ds1 = makeDs(tldKey)
    const ds2 = makeDs(tldKey)
    ds1.data.algorithm = 252

    const prover = makeProver(
      {
        'tld.': {
          DNSKEY: makeSignedResponse([tldKey], [tldKey]),
          DS: makeSignedResponse([ds1, ds2], [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )
    const result = await prover.queryWithProof('DNSKEY', 'tld.')
    expect(result.answer.records.length).toEqual(1)
    expect(result.proofs.length).toEqual(2)
  })

  it('throws an exception if no valid DS records are found', async () => {
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    const ds1 = makeDs(tldKey)
    ds1.data.algorithm = 252

    const prover = makeProver(
      {
        'tld.': {
          DNSKEY: makeSignedResponse([tldKey], [tldKey]),
          DS: makeSignedResponse([ds1], [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )

    try {
      await prover.queryWithProof('DNSKEY', 'tld.')
    } catch (e) {
      expect((e as Error).name).toEqual('NoValidDsError')
    }
  })

  it('throws an exception if no valid DNSKEY records are found', async () => {
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    tldKey.data.algorithm = 252

    const prover = makeProver(
      {
        'test.tld.': {
          TXT: makeSignedResponse(
            [
              {
                name: 'test.tld.',
                type: 'TXT',
                data: [Buffer.from('test')],
              },
            ],
            [tldKey],
          ),
        },
        'tld.': {
          DNSKEY: makeSignedResponse([tldKey], [tldKey]),
          DS: makeDsResponse(tldKey, [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )

    try {
      await prover.queryWithProof('TXT', 'test.tld.')
    } catch (e) {
      expect((e as Error).name).toEqual('NoValidDnskeyError')
    }
  })

  it('throws an exception if no valid self-signed DNSKEY records are found', async () => {
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    tldKey.data.algorithm = 252

    const prover = makeProver(
      {
        'tld.': {
          DNSKEY: makeSignedResponse([tldKey], [tldKey]),
          DS: makeDsResponse(tldKey, [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )

    try {
      await prover.queryWithProof('DNSKEY', 'tld.')
    } catch (e) {
      expect((e as Error).name).toEqual('NoValidDsError')
    }
  })

  it('requires that the DNSKEY be in the chain of trust', async () => {
    // In the situation that a self-signed DNSKEY RRSET has multiple keys and
    // multiple signatures, but only one of those keys has a DS record in the
    // parent zone, we should only accept the signature with the DNSKEY that
    // is validated by the DS record. This test checks that situation.

    // Create a root key and two TLD keys
    const rootKey = makeKey('.')
    const tldKey = makeKey('tld.')
    const tldKey2 = makeKey('tld.')

    const prover = makeProver(
      {
        'tld.': {
          // DNSKEY RRSet is signed only with tldKey
          DNSKEY: makeSignedResponse([tldKey, tldKey2], [tldKey]),
          // DS RRSet hashes only tldKey2 - no chain of trust
          DS: makeDsResponse(tldKey2, [rootKey]),
        },
        '.': {
          DNSKEY: makeSignedResponse([rootKey], [rootKey]),
        },
      },
      rootKey,
    )

    try {
      await prover.queryWithProof('DNSKEY', 'tld.')
    } catch (e) {
      expect((e as Error).name).toEqual('NoValidDsError')
    }
  })

  it('sorts RRs correctly for canonical form', () => {
    // Sort order should be as below.
    // If we sort by the whole RR, we end up sorting them in reverse order, due to the length field.
    const rrs = [
      {
        name: 'test',
        type: 'DS' as const,
        class: 'IN',
        flush: false,
        data: {
          keyTag: 0x0123,
          algorithm: 8,
          digestType: 1,
          digest: Buffer.from('FFFFFFFF', 'hex'),
        },
      },
      {
        name: 'test',
        type: 'DS' as const,
        class: 'IN',
        flush: false,
        data: {
          keyTag: 0x4567,
          algorithm: 8,
          digestType: 1,
          digest: Buffer.from('0000', 'hex'),
        },
      },
    ]
    const ss = new SignedSet<packet.Ds>(rrs, {
      name: rrs[0].name,
      type: 'RRSIG',
      class: rrs[0].class,
      data: {
        typeCovered: rrs[0].type,
        algorithm: 8,
        labels: 1,
        originalTTL: 3600,
        expiration: Date.now() / 1000 + 3600,
        inception: Date.now() / 1000 - 3600,
        keyTag: 12345,
        signersName: '.',
        signature: Buffer.of(),
      },
    })
    // Sort and encode
    const wire = ss.toWire(true)
    const decoded = SignedSet.fromWire<packet.Ds>(wire, Buffer.of())
    expect(decoded.records).toStrictEqual(rrs)
  })
})
