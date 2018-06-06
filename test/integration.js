
const dns = require("dnssec-oracle/lib/dns.js");
const sinon = require('sinon')
const fs = require('fs');
const packet = require('dns-packet');
const DnsProve  = require('../lib/dnsprover');
const namehash = require('eth-ens-namehash');
const DNSSEC = artifacts.require("dnssec-oracle/contracts/DNSSEC.sol");
const DNSRegistrar = artifacts.require("dnsregistrar/contracts/dnsregistrar.sol");
const ENSImplementation = artifacts.require("dnsregistrar/contracts/ensimplementation.sol");

const hexEncodeTXT = function(rec) {
  var buf = new Buffer(4096);
  debugger;
  var off = dns.encodeTXT(buf, 0, rec);
  return "0x" + buf.toString("hex", 0, off);
}

contract('DNSSEC', function(accounts) {
  const owner = accounts[0];
  const provider = web3.currentProvider;
  const address =  DNSSEC.address;

  let stub = sinon.stub(global, 'fetch').callsFake(function(input) {
    return {
      buffer: async ()=>{
        // eg: AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA
        let fileName = input.split('=')[2];
  
        let filePath = './test/fixtures/' + fileName + '.json';
        if (fs.existsSync(filePath)) {
          let response = fs.readFileSync(filePath, 'utf8');
          let decoded = JSON.parse(response, (k, v) => {
            // JSON.stringify cannot serialise Buffer as is so changes it's data format
            // to {data:{type:"Buffer", data:[1,2,1]}}.
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

  it('should accept mocked DNSSEC records', async function() {
    const registrar = await DNSRegistrar.deployed();
    const ens =  await ENSImplementation.deployed();

    // Step 1. Look up dns entry
    const dnsprove  = new DnsProve(provider);
    const dnsResult = await dnsprove.lookup('_ens.matoken.xyz');
    const oracle    = await dnsprove.getOracle(address);
    // Step 2. Checks that the result is found and is valid.
    assert.equal(dnsResult.found, true);
    assert.equal(dnsResult.owner, owner);
    assert.equal(dnsResult.proofs.length, 6);
    assert.equal(dnsResult.proofs[0].name, '.');

    // Step 3. Submit each proof to DNSSEC oracle
    let proofs = dnsResult.proofs;
    for(let i = 0; i < proofs.length; i++){
      var proof = proofs[i];
      let rrdata;
      let result = await oracle.knownProof(proof);
      assert.equal(parseInt(result), 0);
      await oracle.submitProof(proof, proofs[i-1], {from:owner})
      result = await oracle.knownProof(proof);
      assert.notEqual(parseInt(result), 0);
    }
    // Step 4. Use the last rrdata as a proof to claim the ownership
    var proof =  '0x' + proofs[proofs.length -1].rrdata.toString('hex');
    let name = dns.hexEncodeName("matoken.xyz.");
    let tx = await registrar.claim(name, proof, {from:owner});
    assert.equal(parseInt(tx.receipt.status), 1);
    // Step 5. Confirm that the domain is owned by thw DNS record owner.
    let result = await ens.owner.call(namehash.hash("matoken.xyz"));
    assert.equal(result, owner);
  });
});
