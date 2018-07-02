# dnsprove.js 

## Functionalities

- Fetches DNS information of given domain name and type
- Validates DNS reponses and constructs proofs
- Submits the proofs into DNSSEC(Domain Name System Security Extensions) Oracle smart contract
- Works from both browser and from node.js

## Installing

```
npm install '@ensdomains/dnsprovejs' --save
```

## Usage

```js
var provider  = web3.currentProvider;
var DnsProve  = require('dnsprove');
var dnsprove  = new DnsProve(provider);
if(!dnsResult.found) throw('DNS entry not found');

var dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz');
var oracle    = await dnsprove.getOracle('0x123...');
var proofs = dnsResult.proofs;
for(i = 0; i < proofs.length; i++){
  var proof = proofs[i];
  if(!await oracle.knownProof(proof)){
    await oracle.submitProof(proof, proofs[i-1], {from:address})
  }
}
```

or you can use `prove` function to batch up the process above

```js
    let oracleAddress = '0x123...';
    let proofs = await dnsprove.prove('_ens.matoken.xyz', oracleAddress);
    await proofs.submit({from:address});
```

## API

### `DnsProve`

- `lookup(type, name)` takes DNS record type (currently only `TXT` is supported) and name. It returns `DnsResult` object.
- `getOracle(address)` returns DNSSEC oracle(`Oracle`) object.
- `prove(name)` looks up DNS record, checks which proofs are already subitted in DNSSEC oracle, then returns `OracleProver` object. 

### `DnsResult`

- `found` is a proparty containing `true` if the given DNS record is found.
- `proofs` is an array of proofs which can be submitted to `Oracle` contract.

### `Oracle`

`Oracle` is a wrapper object of `DNSSEC.sol` Oracle smart contract.

- `known(proof)` returns true if the given proof already exists in `Oracle`.
- `submitProof(proof, prevProof, params)` submits a proof to Oracle contract. If `prevProof` is `null`, the oracle contract uses hard-coded root anchor proof to validate the validity of the proof given. `params` is used to pass any params to be sent to transaction, such as `{from:address}`.

### `OracleProver`

- `proofs` is an array of all proofs associated with the DNS entry
- `total` is total number of `proofs`
- `unproven` = number of proofs yet to be submitted int DNSSEC Oracle
- `owner` is an address which is in embedded `_ens.domain.tld`. This owner will be the owner of the given domain name regardless of who submit the proof into DNSSEC Oracle.
- `submit()` sends all unproven proofs into DNSSEC Oracle.
- `submit(index)` sends a single proof (specified by index of `proofs` array) into DNSSEC Oracle. Mostly used for testing purpose.

## Testing

```
  npm run test
```

### Running demo

```
# The test page extracts contract info from build/contracts/*.json 
truffle migrate --network development
# compile example/main.js into example/dist/bundle.js
npm run example
cd example
python -m SimpleHTTPServer 
open http://localhost:8000
```

## TODO

- Raise an error message when proofs are not valid.
- Raise an error message when failed to submit proof to oracle
- Add unit tests
- Support for `submitRRSets`
