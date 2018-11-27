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


if(dnsResult.found){
  for(i = 0; i < proofs.length; i++){
    var proof = proofs[i];
    if(!await oracle.knownProof(proof)){
      await oracle.submitProof(proof, proofs[i-1], {from:address})
    }
  }
}else{
  let lastProof = proofs[proofs.lengh -1]
  // The record no longer exists.
  if(dnsResult.nsec && (await oracle.knownProof(lastProof))){
    await oracle.deleteProof(lastProof, proofs[proofs.lengh -2], {from:address})
  }
}
```

Or you can submit all in one transaction.

```js
  let dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
  let oracle    = await dnsprove.getOracle(address);
  await oracle.submitAll(dnsResult, {from:nonOwner});
```

## API

Please refer to [the doc](https://dnsprovejs.readthedocs.io/en/doc)

## Testing

```
  npm run test
```

