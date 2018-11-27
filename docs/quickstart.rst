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

Or you can submit all in one transaction.

.. code-block:: javascript

        let dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
        let oracle    = await dnsprove.getOracle(address);
        await oracle.submitAll(dnsResult, {from:nonOwner});
        

