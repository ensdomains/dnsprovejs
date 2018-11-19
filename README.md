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

### `DnsProve`

- `lookup(type, name)` takes DNS record type and name. It returns `DnsResult` object.
- `getOracle(address)` returns DNSSEC oracle(`Oracle`) object.

### `DnsResult`

- `found` is a proparty containing `true` if the given DNS record is found.
- `nsec` is a proparty containing `true` if the given DNS record type is either `NSEC` or `NSEC3`
- `results` is an array of DNS records.
- `proofs` is an array of proofs which can be submitted to `Oracle` contract.
- `lastProof` is a hex representation of the last resource record data (aka rrdata)

### `Oracle`

`Oracle` is a wrapper object of `DNSSEC.sol` Oracle smart contract.

- `submitAll(dnsresult, params)` sends all unproven proofs into DNSSEC Oracle as one transaction in a batch.
- `getAllProofs(dnsresult)` returns all the proofs needs to be submitted into DNSSEC Oracle. It travarses from the leaf of the chain of proof to check if proof in DNSSEC Oracle and the one from DNS record matches with valid inception value. This function is used so that it can pass the necessary proof to `dnsregistrar.proveAndClaim` function.
- `submitProof(proof, prevProof, params)` submits a proof to Oracle contract. If `prevProof` is `null`, the oracle contract uses hard-coded root anchor proof to validate the validity of the proof given. `params` is used to pass any params to be sent to transaction, such as `{from:address}`.
- `deleteProof(type, name, proof, prevProof, params)` deletes a proof
- `knownProof(proof)` returns a `proof` object with the following fields.


|field    |value    |
|---------|----     |
|inception|inception time (the time the signature was generated) stored in DNSSEC oracle|
|inceptionToProve|inception time constructed from DNS record|
|inserted|the time the record was inserted into DNSSEC oracle|
|hash|hash of proof stored in DNSSEC oracle |
|hashToProve|hash of proof constructed from DNS record|
|validInception|returns true if inception in DNSSEC oracle is older than the one from DNS record. Returns false if the record from DNS record is older (happens when cached)|
|matchedHash|returns true when hash from DNS oracle and hash from DNS record matches|
|matched|returns true if inception is valid and hash is matched|


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
