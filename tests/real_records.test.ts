import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import type { DnskeyAnswer, DSAnswer } from 'dns-packet'
import {
  DNSProver,
  getKeyTag,
  type ProvableAnswer,
  type RecordAnswer,
} from '../src/prove.js'

// Validates the chain of trust by checking for matching key tags.
function checkKeyTags(result: ProvableAnswer<RecordAnswer>) {
  let last = result.answer
  for (const proof of result.proofs.reverse()) {
    switch (proof.records[0].type) {
      case 'DNSKEY': {
        const keyTags = proof.records.map((r) => getKeyTag(r as DnskeyAnswer))
        assert.ok(keyTags.includes(last.signature.data.keyTag))
        break
      }
      case 'DS': {
        const dsTags = proof.records.map((r) => (r as DSAnswer).data.keyTag)
        const validKeys = (last.records as DnskeyAnswer[]).filter((r) =>
          dsTags.includes(getKeyTag(r)),
        )
        assert.notEqual(validKeys.length, 0)
        assert.ok(
          validKeys
            .map((r) => getKeyTag(r))
            .includes(last.signature.data.keyTag),
        )
      }
    }
    last = proof
  }
}

describe('dnsprovejs', () => {
  it('queries TXT _ens.taytems.xyz correctly on cloudflare dns', async () => {
    const prover = DNSProver.create('https://cloudflare-dns.com/dns-query')
    const result = (await prover.queryWithProof('TXT', '_ens.taytems.xyz'))!
    checkKeyTags(result)
    assert.partialDeepStrictEqual(result.answer, {
      records: [{ name: '_ens.taytems.xyz', type: 'TXT' }],
      signature: { name: '_ens.taytems.xyz' },
    })
    assert.deepStrictEqual(result.proofs.length, 5)
  })

  it('queries TXT _ens.taytems.xyz correctly on google dns', async () => {
    const prover = DNSProver.create('https://dns.google/dns-query')
    const result = (await prover.queryWithProof('TXT', '_ens.taytems.xyz'))!
    checkKeyTags(result)
    assert.partialDeepStrictEqual(result.answer, {
      records: [{ name: '_ens.taytems.xyz', type: 'TXT' }],
      signature: { name: '_ens.taytems.xyz' },
    })
    assert.deepStrictEqual(result.proofs.length, 5)
  })
})
