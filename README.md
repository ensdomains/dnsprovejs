# dnsprove.js 

## Functionalities

- Fetches DNS information of given domain name and type
- Validates DNS reponse and constructs proofs
- Submits the proofs into DSNSEC Oracle smart contract
- Works from both browser and from node.js

## Installing

```
npm install '@ensdomains/dnsprovejs' --save
```

## Usage

```js
var Web3      = require('web3');
var provider  = new Web3.providers.HttpProvider();
var DnsProve  = require('dnsprove');
var dnsprove  = new DnsProve(provider);
dnsResult.found // returns true/false
var dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz');
var oracle    = await dnsprove.getOracle('0x123...');
assert(dnsResult.found);
var proofs = dnsResult.proofs;
for(i = 0; i < proofs.length; i++){
  var proof = proofs[i];
  // proof.rrsig
  // proof.signature
  if(!await oracle.knownProof(proof)){
    await oracle.submitProof(proof, proofs[i-1], {from:address})
  }
}
```

or you can use `prove` function to batch up the process above

```js
    let oracleAddress = '0x123...';
    let proofs = await dnsprove.prove('_ens.matoken.xyz', oracleAddress);
    // returns error if failed to get proofs.
    proofs.error 
    // displays the number of unproven transactions which you can show to end users.
    proofs.unproven
    // submit all unproven proofs in a batch.
    await proofs.submit({from:address});
```

## Testing

```
  npm run test
```

### Running demo

```
# The test page extracts contract info from build/contracts/*json 
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
