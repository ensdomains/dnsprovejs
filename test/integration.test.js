const dns = require("dnssec-oracle/lib/dns.js");
const dnsprove = require('../index');
const sinon = require('sinon')
const fs = require('fs');
const packet = require('dns-packet');
const realFetch = require('isomorphic-fetch');
const Web3      = require('web3');
const DnsProve  = require('../lib/dnsprover');
const namehash = require('eth-ens-namehash');

// These are test only settings which library itself should not be aware of.
const provider = new Web3.providers.HttpProvider("http://localhost:8545");
const MyContract = require("../build/contracts/DNSSEC.json");
const ENSImplementation = require("../build/contracts/ENSImplementation.json");
const DNSRegistrar = require("../build/contracts/DNSRegistrar.json");
const network = Object.keys(MyContract.networks)[0];
const address = MyContract.networks[network].address;
const registrar_address = DNSRegistrar.networks[network].address;
const ens_address = ENSImplementation.networks[network].address;
const web3 = new Web3(provider);
const registrar = new web3.eth.Contract(DNSRegistrar.abi, registrar_address);
const ens = new web3.eth.Contract(ENSImplementation.abi, ens_address);
const owner = '0xe87529a6123a74320e13a6dabf3606630683c029' // assume you start ganache-cli -s 1

const hexEncodeTXT = function(rec) {
  var buf = new Buffer(4096);
  console.log('111', buf, rec);
  debugger;
  var off = dns.encodeTXT(buf, 0, rec);
  return "0x" + buf.toString("hex", 0, off);
}

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
        // Swap address with dnsregistrar owner as only the address owner can register
        if (decoded.answers[0].name == '_ens.matoken.xyz' && decoded.answers[0].type == 'TXT'){
          let text = `a=${owner}`
          decoded.answers[0].data = Buffer.from(text, 'ascii')
        }
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
        await oracle.submitProof(proof, proofs[i-1], {from:owner})
        result = await oracle.knownProof(proof);
        console.log(2, proof.name, proof.type, result)
      }else{
        console.log(3, proof.name, proof.type, result)
      }
    }
    let account = '0x5A384227B65FA093DEC03Ec34e111Db80A040615';
    var proof =  '0x' + proofs[proofs.length -1].rrdata.toString('hex');
    let name = dns.hexEncodeName("matoken.xyz.");
    console.log('claim', name, proof);
    let tx = await registrar.methods.claim(name, proof).send({from:owner});
    expect(tx.status).toBe(true);
    let result = await ens.methods.owner(namehash.hash("matoken.xyz")).call();
    expect(result.toLowerCase()).toBe(owner);
  });
});
