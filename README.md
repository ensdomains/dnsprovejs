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
    var textDomain = '_ens.matoken.xyz';
    var dnsResult = await dnsprove.lookup('TXT', textDomain);
    var oracle    = await dnsprove.getOracle('0x123...');
    var proofs = dnsResult.proofs;

    if(dnsResult.found){
        await oracle.submitAll(dnsResult, {from:nonOwner});
    }else if (dnsResult.nsec){
        await oracle.deleteProof(
            'TXT', textDomain,
            proofs[proofs.length -1],
            proofs[proofs.length -2],
            {from:nonOwner}
        );
    }else{
        throw("DNSSEC is not supported")
    }
```

Alternatively, if you want to submit the proof not only to Oracle contract but also to claim via `dnsregistrar`, then you can call `getAllProofs` and pass the result into the `proveAndClaim` function.

```js
    let dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
    let oracle    = await dnsprove.getOracle(address);
    let data = await oracle.getAllProofs(dnsResult, params);
    await registrar.methods
        .proveAndClaim(encodedName, data[0], data[1])
        .send(params)
```
## API

Please refer to [the doc](https://dnsprovejs.readthedocs.io)

## Testing

```
  npm run test
```

