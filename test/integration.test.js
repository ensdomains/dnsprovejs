const dns = require("dnssec-oracle/lib/dns.js");
const dnsprove = require('../index');
const sinon = require('sinon')
const fs = require('fs');
const packet = require('dns-packet');
const realFetch = require('isomorphic-fetch');
const Web3      = require('web3');
const DnsProve  = require('../lib/dnsprover');
const provider = new Web3.providers.HttpProvider("http://localhost:8545");
const MyContract = require("../build/contracts/DNSSEC.json");
debugger
let network = Object.keys(MyContract.networks)[0];
let address = MyContract.networks[network].address;

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
    var dnsprove  = new DnsProve(provider);
    var dnsResult = await dnsprove.lookup('_ens.matoken.xyz');
    var oracle    = await dnsprove.getOracle(address);
    expect(dnsResult.found).toBe(true);
    expect(dnsResult.proofs.length).toBe(6);
    expect(dnsResult.proofs[0].name).toBe('.');
    let proofs = dnsResult.proofs;
    for(let i = 0; i < proofs.length; i++){
      var proof = proofs[i];
      let rrdata;

      let result = await oracle.knownProof(proof);
      if(parseInt(result) == 0){
        console.log(1, proof.name, proof.type, result)
        await oracle.submitProof(proof, proofs[i-1], {from:'0xe87529a6123a74320e13a6dabf3606630683c029'})
        result = await oracle.knownProof(proof);
        console.log(2, proof.name, proof.type, result)
        }else{
        console.log(3, proof.name, proof.type, result)
      }
    }    
  });
});
