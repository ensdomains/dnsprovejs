const sinon = require('sinon');
const fs = require('fs');
const packet = require('dns-packet');
const DnsProve = require('../lib/dnsprover');
const namehash = require('eth-ens-namehash');
const sha3 = require('web3').utils.sha3;
const dns = require('@ensdomains/dnssec-oracle/lib/dns.js');
const DNSSEC = artifacts.require('@ensdomains/dnssec-oracle/DNSSEC.sol');
const DummyAlgorithm = artifacts.require(
  '@ensdomains/dnssec-oracle/DummyAlgorithm.sol'
);
const DummyDigest = artifacts.require(
  '@ensdomains/dnssec-oracle/DummyDigest.sol'
);
const ENSImplementation = artifacts.require(
  '@ensdomains/dnsregistrar/ENSImplementation.sol'
);
const DNSRegistrar = artifacts.require(
  '@ensdomains/dnsregistrar/DNSRegistrar.sol'
);
const tld = 'xyz';

function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

contract('DNSSEC', function(accounts) {
  const owner = accounts[0];
  const nonOwner = accounts[1];
  const provider = web3.currentProvider;

  let stub = sinon.stub(global, 'fetch').callsFake(function(input) {
    return {
      buffer: async () => {
        // eg: AAEBAAABAAAAAAABBF9lbnMHbWF0b2tlbgN4eXoAABAAAQAAKRAAAACAAAAA
        let fileName = input.split('=')[2];
        let filePath = './test/fixtures/' + fileName + '.json';
        let response;
        if (fs.existsSync(filePath)) {
          response = fs.readFileSync(filePath, 'utf8');
        } else {
          response = fs.readFileSync('./test/fixtures/notfound.json', 'utf8');
        }
        let decoded = JSON.parse(response, (k, v) => {
          // JSON.stringify cannot serialise Buffer as is so changes it's data format
          // to {data:{type:"Buffer", data:[1,2,1]}}.
          // You need to transform back to Buffer
          // such as {data: new Buffer([1,2,1]) }
          if (
            v !== null &&
            typeof v === 'object' &&
            'type' in v &&
            v.type === 'Buffer' &&
            'data' in v &&
            Array.isArray(v.data)
          ) {
            v = new Buffer(v.data);
          }
          return v;
        });
        // Swap address with dnsregistrar owner as only the address owner can register
        if (
          decoded.answers.length > 0 &&
          decoded.answers[0].name == '_ens.matoken.xyz' &&
          decoded.answers[0].type == 'TXT'
        ) {
          let text = `a=${owner}`;
          decoded.answers[0].data = Buffer.from(text, 'ascii');
        }
        return packet.encode(decoded);
      }
    };
  });

  let address, ens, dummyAlgorithm, dummyDigest, registrar, dnssec;
  beforeEach(async function() {
    ens = await ENSImplementation.new();
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

  it('lookup should accept mocked DNSSEC records', async function() {
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
      await oracle.submitProof(proof, proofs[i - 1], { from: owner });
      result = await oracle.knownProof(proof);
      assert.notEqual(parseInt(result), 0);
    }
    // Step 4. Use the last rrdata as a proof to claim the ownership
    var proof = '0x' + proofs[proofs.length - 1].rrdata.toString('hex');
    let name = hexEncodeName('matoken.xyz');
    let tx = await registrar.claim(name, proof, { from: owner });
    assert.equal(parseInt(tx.receipt.status), 1);
    // Step 5. Confirm that the domain is owned by thw DNS record owner.
    let result = await ens.owner.call(namehash.hash('matoken.xyz'));
    assert.equal(result, owner);
  });

  it('prove should return transactions which need proving', async function() {
    const dnsprove = new DnsProve(provider);
    let dnsResult = await dnsprove.lookup('TXT', '_ens.matoken.xyz', address);
    let oracle = await dnsprove.getOracle(address);
    let prover = await oracle.getProver(dnsResult);
    assert.equal(prover.total, 6);
    assert.equal(prover.unproven, 6);
    assert.equal(
      prover.lastProof,
      '0x' + prover.proofs[5].rrdata.toString('hex')
    );
    await oracle.submitProof(prover.proofs[0], null, { from: nonOwner });
    prover = await oracle.getProver(dnsResult);
    assert.equal(prover.total, 6);
    assert.equal(prover.unproven, 5);

    await oracle.submit(dnsResult, { from: nonOwner });
    prover = await oracle.getProver(dnsResult);
    assert.equal(prover.total, 6);
    assert.equal(prover.unproven, 0);
  });

  it('raises error if the DNS entry does not exist', async function() {
    const dnsprove = new DnsProve(provider);
    let dnsResult = await dnsprove.lookup('TXT', 'example.com', address);
    assert.equal(dnsResult.found, false);
  });
});
