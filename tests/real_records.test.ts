import * as packet from 'dns-packet'
import { DNSProver, getKeyTag, ProvableAnswer } from '../src/prove'

import { describe, expect, it } from 'bun:test'

// Validates the chain of trust by checking for matching key tags.
function checkKeyTags(result: ProvableAnswer<any>) {
  let last = result.answer
  for (const proof of result.proofs.reverse()) {
    switch (proof.records[0].type) {
      case 'DNSKEY':
        const keyTags = proof.records.map((r) => getKeyTag(r as packet.Dnskey))
        expect(keyTags).toContain(last.signature.data.keyTag)

        break
      case 'DS':
        const dsTags = proof.records.map((r) => (r as packet.Ds).data.keyTag)
        const validKeys = last.records.filter((r: packet.Dnskey) =>
          dsTags.includes(getKeyTag(r)),
        )
        expect(validKeys).not.toBeEmpty()
        expect(validKeys.map((r) => getKeyTag(r))).toContain(
          last.signature.data.keyTag,
        )
    }
    last = proof
  }
}

describe('dnsprovejs', () => {
  it('queries TXT _ens.taytems.xyz correctly on cloudflare dns', async () => {
    const prover = DNSProver.create('https://cloudflare-dns.com/dns-query')
    const result = await prover.queryWithProof('TXT', '_ens.taytems.xyz')
    checkKeyTags(result)
    expect(result.answer).toMatchObject({
      records: [{ name: '_ens.taytems.xyz', type: 'TXT' }],
      signature: { name: '_ens.taytems.xyz' },
    })
    expect(result.proofs.length).toEqual(5)
  })

  it('queries TXT _ens.taytems.xyz correctly on google dns', async () => {
    const prover = DNSProver.create('https://dns.google/dns-query')
    const result = await prover.queryWithProof('TXT', '_ens.taytems.xyz')
    checkKeyTags(result)
    expect(result.answer).toMatchObject({
      records: [{ name: '_ens.taytems.xyz', type: 'TXT' }],
      signature: { name: '_ens.taytems.xyz' },
    })
    expect(result.proofs.length).toEqual(5)
  })
})
