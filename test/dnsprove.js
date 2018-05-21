var dnssec = artifacts.require("dnssec-oracle/contracts/DNSSEC.sol");
var dns = require("dnssec-oracle/lib/dns.js");
var dnsprove = require('../index');
var nvcr = require('nock-vcr');

async function verifySubmission(instance, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var tx = await instance.submitRRSet(data, sig, proof);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  assert.equal(tx.logs.length, 1);
  return tx;
}

contract('DNSSEC', function(accounts) {
  it('should have a default algorithm and digest set', async function() {
    var instance = await dnssec.deployed();
    assert.notEqual(await instance.algorithms(8), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.algorithms(253), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(2), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(253), "0x0000000000000000000000000000000000000000");
  });

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    nvcr.insertCassette('_ens_matoken_xyz.txt');
    var results = await dnsprove.queryWithProof('TXT', '_ens.matoken.xyz')
    var test_rrsets = results.map((result)=>{ 
      packed1 = dnsprove.pack(result[1], result[0])
      packed = packed1.map((p)=>{
        return p.toString('hex')
      });
      var name = result[0].name;
      if(name != '.'){
        name = name +  '.';
      }
      var data = packed[0];
      var sig = packed[1];
      packed.unshift(result[0].name);
      return [name, data, sig]
    })

    for(var rrset of test_rrsets) {
      console.log(rrset[0]);
      var tx = await verifySubmission(instance, "0x" + rrset[1], "0x" + rrset[2], proof);
      assert.equal(tx.logs.length, 1);
      assert.equal(tx.logs[0].event, 'RRSetUpdated');
      proof = tx.logs[0].args.rrset;
    }
    nvcr.ejectCassette()
  });
});
