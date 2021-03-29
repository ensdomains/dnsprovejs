*******************
Quick start
*******************

Installing
===========

.. code-block:: console

        npm install '@ensdomains/dnsprovejs' --save


Usage
=====


.. code-block:: javascript

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

Alternatively, if you want to submit the proof not only to Oracle contract but also to claim via `dnsregistrar`, then you can call `getAllProofs` and pass the result into the `proveAndClaim` function.

.. code-block:: javascript

        let dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
        let oracle    = await dnsprove.getOracle(address);
        let data = await oracle.getAllProofs(dnsResult, params);
        await registrar.methods
            .proveAndClaim(encodedName, data[0], data[1])
            .send(params)

DnsRegistrar
============

The example above demonstrated the case to call `proveAndClaim` smart contract function directly but we have a wrapper libray
at `DNSregistrar <https://github.com/ensdomains/dnsregistrar>`_ which calls DNSSEC Oracle and DnsRegistrar in one function call.

.. code-block:: javascript

        var DNSRegistrarJs = require('@ensdomains/dnsregistrar');
        dnsregistrar = new DNSRegistrarJs(provider, dnsregistraraddress);
        dnsregistrar.claim('foo.test').then((claim)=>{
            claim.submit({from:account});
        })
