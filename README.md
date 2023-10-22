# dnsprove.js

A TypeScript/JavaScript library for querying and validating DNSSEC data from DNS.

## Installing

```
bun add @ensdomains/dnsprovejs
```

## Usage

```js
import { DNSProver } from '@ensdomains/dnsprovejs'
const prover = DNSProver.create('https://cloudflare-dns.com/dns-query')
const result = await prover.queryWithProof('TXT', textDomain)
```

## API

Please refer to [the doc](https://dnsprovejs.readthedocs.io)

## Testing

```
bun test
```
