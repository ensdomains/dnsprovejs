const nock = require('nock');
const sinon = require('sinon');
const fs = require('fs');
const packet = require('dns-packet');
const DnsProve = require('../lib/dnsprover');
const namehash = require('eth-ens-namehash');
const sha3 = require('web3').utils.sha3;
const dns = require('@ensdomains/dnssec-oracle/lib/dns.js');
const DNSSEC = artifacts.require('@ensdomains/dnssec-oracle/DNSSECImpl.sol');
const DummyAlgorithm = artifacts.require(
  '@ensdomains/dnssec-oracle/DummyAlgorithm.sol'
);
const DummyDigest = artifacts.require(
  '@ensdomains/dnssec-oracle/DummyDigest.sol'
);
const ENSRegistry = artifacts.require(
  '@ensdomains/ens/ENSRegistry.sol'
);
const DNSRegistrar = artifacts.require(
  '@ensdomains/dnsregistrar/DNSRegistrar.sol'
);
const tld = 'xyz';
const gas = '1000000';
function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

contract('DNSSEC', function(accounts) {
  const owner = accounts[0];
  const nonOwner = accounts[1];
  const provider = web3.currentProvider;

  // let stub = sinon.stub(global, 'fetch').callsFake(function(input) {
  //   return {
  //     buffer: async () => {
  //       console.log("input", input)
  //       // eg: AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA
  //       let fileName = input.split('=')[2];
  //       let filePath = './test/fixtures/' + fileName + '.json';
  //       let response;
  //       if (fs.existsSync(filePath)) {
  //         response = fs.readFileSync(filePath, 'utf8');
  //       } else {
  //         response = fs.readFileSync('./test/fixtures/notfound.json', 'utf8');
  //       }
  //       let decoded = JSON.parse(response, (k, v) => {
  //         // JSON.stringify cannot serialise Buffer as is so changes it's data format
  //         // to {data:{type:"Buffer", data:[1,2,1]}}.
  //         // You need to transform back to Buffer
  //         // such as {data: new Buffer([1,2,1]) }
  //         if (
  //           v !== null &&
  //           typeof v === 'object' &&
  //           'type' in v &&
  //           v.type === 'Buffer' &&
  //           'data' in v &&
  //           Array.isArray(v.data)
  //         ) {
  //           v = new Buffer(v.data);
  //         }
  //         return v;
  //       });
  //       // Swap address with dnsregistrar owner as only the address owner can register
  //       if (
  //         decoded.answers.length > 0 &&
  //         decoded.answers[0].name == '_ens.matoken.xyz' &&
  //         decoded.answers[0].type == 'TXT'
  //       ) {
  //         let text = `a=${owner}`;
  //         decoded.answers[0].data = Buffer.from(text, 'ascii');
  //       }
  //       let res = packet.encode(decoded);
  //       // console.log('res', decoded)
  //       return res;
  //     }
  //   };
  // });

  let address, ens, dummyAlgorithm, dummyDigest, registrar, dnssec;
  beforeEach(async function() {
    ens = await ENSRegistry.new();
    dummyAlgorithm = await DummyAlgorithm.new();
    dummyDigest = await DummyDigest.new();
    let anchors = dns.anchors;
    anchors.push(dns.dummyAnchor);
    dnssec = await DNSSEC.new(dns.encodeAnchors(anchors));
    address = dnssec.address;

    assert.equal(await dnssec.anchors.call(), dns.encodeAnchors(anchors));
    registrar = await DNSRegistrar.new(
      dnssec.address,
      ens.address,
      hexEncodeName(tld),
      namehash.hash(tld)
    );

    assert.equal(await registrar.oracle.call(), dnssec.address);
    assert.equal(await registrar.ens.call(), ens.address);
    assert.equal(await registrar.rootDomain.call(), hexEncodeName(tld));
    assert.equal(await registrar.rootNode.call(), namehash.hash(tld));

    await ens.setSubnodeOwner(0, sha3(tld), registrar.address);
    assert.equal(await ens.owner.call(namehash.hash(tld)), registrar.address);

    await dnssec.setAlgorithm(253, dummyAlgorithm.address);
    await dnssec.setAlgorithm(254, dummyAlgorithm.address);
    await dnssec.setDigest(253, dummyDigest.address);

    assert.equal(await dnssec.algorithms.call(253), dummyAlgorithm.address);
    assert.equal(await dnssec.algorithms.call(254), dummyAlgorithm.address);
    assert.equal(await dnssec.digests.call(253), dummyDigest.address);
  });

  afterEach(async function(){
    nock.cleanAll()
  })

  describe('_ens.matoken.xyz', async function(){
    beforeEach(async function() {
      let text = Buffer.from(`a=${owner}`, 'ascii');
      let buffer = new Buffer([]);
  
      function rrsigdata(typeCoverd, signersName, override){
        let obj = {
          "typeCovered": typeCoverd,
          "algorithm": 253,
          "labels": 1,
          "originalTTL": 300,
          "expiration": 2528174800,
          "inception": 1526834834,
          "keyTag": 1277,
          "signersName": signersName,
          "signature": buffer
        }
        return Object.assign(obj, override);
      }
  
      let dnskeydata = {
        "flags": 256,
        "algorithm": 253,
        "key": buffer
      }
  
      let dnskeydata2 = {
        "flags": 257,
        "algorithm": 253,
        "key": buffer
      }
  
      let dsdata = {
        "keyTag": 1277,
        "algorithm": 253,
        "digestType": 253,
        "digest": buffer
      }
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA')
                  .once()
                  .reply(200, packet.encode({
                    questions: [ { name: '_ens.matoken.xyz', type: 'TXT', class: 'IN' } ],
                    answers: [
                      { name: '_ens.matoken.xyz', type: 'TXT', class: 'IN',  data: text },
                      { name: '_ens.matoken.xyz', type: 'RRSIG',class: 'IN', data: rrsigdata('TXT', 'matoken.xyz', {labels:3}) }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA==')
                  .reply(200, packet.encode({
                    questions: [ { name: '_ens.matoken.xyz', type: 'TXT', class: 'IN' } ],
                    answers: [
                      { name: '_ens.matoken.xyz', type: 'TXT', class: 'IN',  data: text },
                      { name: '_ens.matoken.xyz', type: 'RRSIG',class: 'IN', data: rrsigdata('TXT', 'matoken.xyz', {labels:3}) }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABB21hdG9rZW4DeHl6AAAwAAEAACkQAAAAgAAAAA==')
                  .reply(200, packet.encode({
                    questions: [ { name: 'matoken.xyz', type: 'DNSKEY', class: 'IN' } ],
                    answers: [
                      { name: 'matoken.xyz', type: 'DNSKEY', class: 'IN', data: dnskeydata },
                      { name: 'matoken.xyz', type: 'RRSIG',  class: 'IN', data: rrsigdata('DNSKEY', 'matoken.xyz', { labels: 2}) }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABB21hdG9rZW4DeHl6AAArAAEAACkQAAAAgAAAAA==')
                  .reply(200, packet.encode({
                    questions: [ { name: 'matoken.xyz', type: 'DS', class: 'IN' } ],
                    answers: [
                      { name: 'matoken.xyz', type: 'DS', class: 'IN', data: dsdata },
                      { name: 'matoken.xyz', type: 'RRSIG',  class: 'IN', data: rrsigdata('DS', 'xyz', { labels:2 }) }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABA3h5egAAMAABAAApEAAAAIAAAAA=')
                  .reply(200, packet.encode({
                    questions: [ { name: 'xyz', type: 'DNSKEY', class: 'IN' } ],
                    answers: [
                      { name: 'xyz', type: 'DNSKEY', class: 'IN', data: dnskeydata },
                      { name: 'xyz', type: 'DNSKEY', class: 'IN', data: dnskeydata2 },
                      { name: 'xyz', type: 'RRSIG',  class: 'IN', data: rrsigdata('DNSKEY', 'xyz') }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABA3h5egAAKwABAAApEAAAAIAAAAA=')
                  .reply(200, packet.encode({
                    questions: [ { name: 'xyz', type: 'DS', class: 'IN' } ],
                    answers: [
                      { name: 'xyz', type: 'RRSIG',  class: 'IN', data: rrsigdata('DS', '.') },
                      { name: 'xyz', type: 'DS', class: 'IN', data: dsdata }
                    ]
                  }));
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABAAAwAAEAACkQAAAAgAAAAA==')
                  .reply(200, packet.encode({
                    questions: [ { name: '.', type: 'DNSKEY', class: 'IN' } ],
                    answers: [
                      { name: '.', type: 'DNSKEY', class: 'IN', data: dnskeydata },
                      { name: '.', type: 'DNSKEY', class: 'IN', data: {flags: 257, algorithm: 253, key: new Buffer([17, 17])} },
                      { name: '.', type: 'RRSIG',  class: 'IN', data: rrsigdata('DNSKEY', '.', { labels:0, keyTag:5647 }) }
                    ]
                  }));
    });
  
    it('submitProof submit a proof', async function() {
      // Step 1. Look up dns entry
      const dnsprove = new DnsProve(provider);
      const dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz');
      const oracle = await dnsprove.getOracle(address);
      // Step 2. Checks that the result is found and is valid.
      assert.equal(dnsResult.found, true);
      assert.equal(
        dnsResult.results[5].rrs[0].data.toString().split('=')[1],
        owner
      );
      assert.equal(dnsResult.proofs.length, 6);
      assert.equal(dnsResult.proofs[0].name, '.');
      // Step 3. Submit each proof to DNSSEC oracle
      let proofs = dnsResult.proofs;
      for (let i = 0; i < proofs.length; i++) {
        var proof = proofs[i];
        let rrdata;
        let result = await oracle.knownProof(proof);
        assert.equal(parseInt(result), 0);
        await oracle.submitProof(proof, proofs[i - 1], { from: owner, gas:gas });
        result = await oracle.knownProof(proof);
        assert.notEqual(parseInt(result), 0);
      }
      // Step 4. Use the last rrdata as a proof to claim the ownership
      var proof = '0x' + proofs[proofs.length - 1].rrdata.toString('hex');
      let name = hexEncodeName('matoken.xyz');
      let tx = await registrar.claim(name, proof, { from: owner, gas:gas });
      assert.equal(parseInt(tx.receipt.status), 1);
      // Step 5. Confirm that the domain is owned by thw DNS record owner.
      let result = await ens.owner.call(namehash.hash('matoken.xyz'));
      assert.equal(result, owner);
    });
  
    it('submitAll submits all proofs at once', async function() {
      const dnsprove = new DnsProve(provider);
      let result = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
      let oracle = await dnsprove.getOracle(address);
      assert.equal((await oracle.getProven(result)), 0);
      await oracle.submitProof(result.proofs[0], null, { from: nonOwner, gas:gas });
      assert.equal((await oracle.getProven(result)), 1);
      await oracle.submitAll(result, { from: nonOwner, gas:gas });
      assert.equal((await oracle.getProven(result)), result.proofs.length);
    });  
  })

  describe('', async function(){
    this.beforeEach(async function(){
      let text = Buffer.from(`a=${owner}`, 'ascii');
      let buffer = new Buffer([]);
  
      function rrsigdata(typeCoverd, signersName, override){
        let obj = {
          "typeCovered": typeCoverd,
          "algorithm": 253,
          "labels": 1,
          "originalTTL": 300,
          "expiration": 2528174800,
          "inception": 1526834834,
          "keyTag": 1277,
          "signersName": signersName,
          "signature": buffer
        }
        return Object.assign(obj, override);
      }
  
      let dnskeydata = {
        "flags": 256,
        "algorithm": 253,
        "key": buffer
      }
  
      let dnskeydata2 = {
        "flags": 257,
        "algorithm": 253,
        "key": buffer
      }
  
      let dsdata = {
        "keyTag": 1277,
        "algorithm": 253,
        "digestType": 253,
        "digest": buffer
      }
  
      nock('https://dns.google.com')
                  .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABAWIAABAAAQAAKRAAAACAAAAA')
                  .once()
                  .reply(200, packet.encode({
                    questions: [ { name: 'b', type: 'TXT', class: 'IN' } ],
                    answers: [
                      { name: 'b', type: 'TXT', class: 'IN',  data: Buffer.from(`a=${owner}`, 'ascii') },
                      // { name: 'b', type: 'TXT', class: 'IN',ttl: 3600,  data: Buffer.from(`foo`, 'ascii') },
                      { name: 'b', type: 'RRSIG',class: 'IN',ttl: 3600, data: rrsigdata('TXT', '.', {labels:1}) }
                    ]
                  }));
  
      nock('https://dns.google.com')
                .get('/experimental?ct=application/dns-udpwireformat&dns=AAEBAAABAAAAAAABAAAwAAEAACkQAAAAgAAAAA==')
                .reply(200, packet.encode({
                  questions: [ { name: '.', type: 'DNSKEY', class: 'IN' } ],
                  answers: [
                    { name: '.', type: 'DNSKEY', class: 'IN', data: {flags: 256, algorithm: 253, key: new Buffer([])} },
                    { name: '.', type: 'DNSKEY', class: 'IN', data: {flags: 257, algorithm: 253, key: new Buffer([17, 17])} },
                    // keytag: 5647 = Empty body, flags == 0x0101(257), algorithm = 253, body = 0x1111(17,17)
                    { name: '.', type: 'RRSIG',  class: 'IN', data: rrsigdata('DNSKEY', '.', { labels:0, keyTag:5647 }) }
                  ]
                }));          
    })

    it('b', async function(){
      accounts
      // Step 1. Look up dns entry
      const dnsprove = new DnsProve(provider);
      const dnsResult = await dnsprove.lookup('TXT', 'b');
      const oracle = await dnsprove.getOracle(address);
      // Step 2. Checks that the result is found and is valid.
      assert.equal(dnsResult.found, true);
      assert.equal(dnsResult.results[1].rrs[0].data.toString().split('=')[1], owner);
      let proofs = dnsResult.proofs
      await oracle.submitProof(proofs[1], null, { from: owner, gas:gas });
      console.log('submitted');
      // await oracle.submitProof(proofs[1], proofs[0], { from: owner, gas:gas });
      // console.log('submitte1');
      let result = await oracle.knownProof(dnsResult.proofs[1]);
      assert.notEqual(parseInt(result), 0);
    })
  })

  // it('raises error if the DNS entry does not exist', async function() {
  //   const dnsprove = new DnsProve(provider);
  //   let dnsResult = await dnsprove.lookup('TXT', 'example.com', address);
  //   assert.equal(dnsResult.found, false);
  // });
});

