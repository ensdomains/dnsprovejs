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
var oracle    = await dnsprove.getOracle('dnsoracle.eth');
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

## Testing

Some of js libraries behaved differently depending on the environment you are in. To make sure it runs correctly, run the following commands to make sure it does not raise any errors.

### Truffle

```
# The migration will generate artifacts from node package into `build/contracts` which seems required step unlike running normal truffle test
truffle migrate --network test
truffle test test/integration.js --network test
```

### Running demo

```
# The test page extracts contract info from build/contracts/*json 
truffle migrate --network --development
npx browserify  lib/dnsprover.js -t babelify --outfile example/dist/bundle.js 
cd example
python -m SimpleHTTPServer 
open http://localhost:8000
```


## TODO

- Raise nice error message when an entry does not exist.
- Raise nice error message when an entry is not valid.
