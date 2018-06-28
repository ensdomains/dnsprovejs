# dnsprove.js 

## Functionalities

- Fetches DNS information of given domain name and type
- Validates DNS reponses and constructs proofs
- Submits the proofs into DNSSEC Oracle smart contract
- Works from both browser and from node.js

## Installing

```
npm install '@ensdomains/dnsprovejs' --save
```

## Usage

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

## Testing

```
  npm run test
```

### Running demo

```
# The test page extracts contract info from build/contracts/*.json 
truffle migrate --network development
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
