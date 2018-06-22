# dnsprove.js 

## Functionalities

- Fetches DNS information of given domain name and type
- Checks if the DNS reponse qualify all the information to be able to add into DNSSEC Oracle
- Submit the entry into DSNSEC Oracle.

## Usage

```js
var Web3      = require('web3');
var provider  = new Web3.providers.HttpProvider();
var DnsProve  = require('dnsprove');
var dnsprove  = new DnsProve(provider);
var dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz');
var oracle    = await dnsprove.getOracle('0x123...');
assert(dnsResult.found);
var proofs = dnsResult.proofs;
for(i = 0; i < proofs.length; i++){
  var proof = proofs[i];
  // proof.rrsig
  // proof.signature
  if(!await oracle.knownProof(proof)){
    await oracle.submitProof(proof)
  }
}
```

or you can use `prove` function to batch up the process above

```js
    let oracleAddress = '0x123...';
    await dnsprove.prove('_ens.matoken.xyz', oracleAddress);
    // displays the number of unproven transactions which you can show to end users.
    proofs.unproven
    // submit all unproven proofs in a batch.
    await proofs.submit();
```

## Testing

```
  npm run test
```

### Running demo

```
# The test page extracts contract info from build/contracts/*json 
truffle migrate --network --development
npm run example
cd example
python -m SimpleHTTPServer 
open http://localhost:8000
```

## TODO

- Raise nice error message when an entry is not valid.
- Add unit tests
