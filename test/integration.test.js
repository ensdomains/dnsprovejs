// const dnssec = artifacts.require("dnssec-oracle/contracts/DNSSEC.sol");
const dns = require("dnssec-oracle/lib/dns.js");
const dnsprove = require('../index');
const sinon = require('sinon')
const fs = require('fs');
const packet = require('dns-packet');
const realFetch = require('isomorphic-fetch');
const Web3      = require('web3');
var DnsProve  = require('../lib/dnsprover');

var stub = sinon.stub(global, 'fetch').callsFake(function(input) {
  return {
    buffer: async ()=>{
      // eg: AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA
      let fileName = input.split('=')[2];

      let filePath = './test/fixtures/' + fileName + '.json';
      if (fs.existsSync(filePath)) {
        let response = fs.readFileSync(filePath, 'utf8');
        let decoded = JSON.parse(response, (k, v) => {
          // JSON.stringify cannot serialise Buffer as is so changes it's data format
          // such as {data:{type:"Buffer", data:[1,2,1]}}.
          // You need to transform back to Buffer
          // such as {data: new Buffer([1,2,1]) }
          if (
            v !== null            &&
            typeof v === 'object' && 
            'type' in v           &&
            v.type === 'Buffer'   &&
            'data' in v           &&
            Array.isArray(v.data)) {
              v = new Buffer(v.data);
          }
          return v;
        });
        return packet.encode(decoded);
      }else{
        // console.log(`***Recording ${input} into ${filePath}`);
        // let encoded = await realFetch(input);
        // let buffer = await encoded.buffer();
        // response = packet.decode(buffer);
        // fs.writeFileSync(filePath, JSON.stringify(response));
        // return buffer;
      }
    }
  };
});

async function verifySubmission(instance, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var tx = await instance.submitRRSet(data, sig, proof);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  assert.equal(tx.logs.length, 1);
  return tx;
}

describe('DNSSEC', function() {

  // Test against real record
  test('should accept real DNSSEC records', async function() {
    // var instance = await dnssec.deployed();
    // var proof = await instance.anchors();
    var provider  = new Web3.providers.HttpProvider();
    var dnsprove  = new DnsProve(provider);
    var dnsResult = await dnsprove.lookup('_ens.matoken.xyz');
    // var oracle    = await dnsprove.getOracle('dnsoracle.eth');
    console.log('dnsResult', JSON.stringify(dnsResult));
    expect(dnsResult.found).toBe(true);
    expect(dnsResult.proofs.length).toBe(6);
    expect(dnsResult.proofs[0].name).toBe('.');
    let proofs = dnsResult.proofs;
    for(let i = 0; i < proofs.length; i++){
      var proof = proofs[i];
      console.log('proof', proof)
      // if(!await oracle.knownProof(proof)){
      //   await oracle.submitProof(proof)
      // }
    }
    
    // for(var rrset of test_rrsets) {
    //   var tx = await verifySubmission(instance, "0x" + rrset[1], "0x" + rrset[2], proof);
    //   assert.equal(tx.logs.length, 1);
    //   assert.equal(tx.logs[0].event, 'RRSetUpdated');
    //   proof = tx.logs[0].args.rrset;
    // }
  });
});
