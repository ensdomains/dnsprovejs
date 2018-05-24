const dnssec = artifacts.require("dnssec-oracle/contracts/DNSSEC.sol");
const dns = require("dnssec-oracle/lib/dns.js");
const dnsprove = require('../index');
const sinon = require('sinon')
const fs = require('fs');
const packet = require('dns-packet');
const realFetch = require('isomorphic-fetch');

var stub = sinon.stub(global, 'fetch').callsFake(function(input) {
  return {
    buffer: async ()=>{
      // eg: AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA
      let fileName = input.split('=')[2];
      let filePath = './test/fixtures/' + fileName + '.json';
      if (fs.existsSync(filePath)) {
        response = fs.readFileSync(filePath, 'utf8');
        decoded = JSON.parse(response, (k, v) => {
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
    var results = await dnsprove.queryWithProof('TXT', '_ens.matoken.xyz')
    results.forEach((result)=>{
      console.log(dnsprove.display(result[0]));
      result[1].forEach((r)=>{
        console.log(dnsprove.display(r));
      })
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
      console.log(`[\"${name}\", \"${data}\", \"${sig}\"],\n`)
      console.log("\n");
    })

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
      var tx = await verifySubmission(instance, "0x" + rrset[1], "0x" + rrset[2], proof);
      assert.equal(tx.logs.length, 1);
      assert.equal(tx.logs[0].event, 'RRSetUpdated');
      proof = tx.logs[0].args.rrset;
    }
  });
});
