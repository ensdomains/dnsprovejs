var DNSSEC = artifacts.require("dnssec-oracle/contracts/DNSSEC.sol");
var rsasha1 = artifacts.require("dnssec-oracle/contracts/RSASHA1Algorithm.sol");
var rsasha256 = artifacts.require("dnssec-oracle/contracts/RSASHA256Algorithm.sol");
var sha1 = artifacts.require("dnssec-oracle/contracts/SHA1Digest.sol");
var sha256 = artifacts.require("dnssec-oracle/contracts/SHA256Digest.sol");
var nsec3sha1 = artifacts.require("dnssec-oracle/contracts/SHA1NSEC3Digest.sol");
var dummyalgorithm = artifacts.require("dnssec-oracle/contracts/DummyAlgorithm.sol");
var dummydigest = artifacts.require("dnssec-oracle/contracts/DummyDigest.sol");
var ENSImplementation = artifacts.require("dnsregistrar/contracts/ensimplementation.sol");
var DNSRegistrar = artifacts.require("dnsregistrar/contracts/dnsregistrar.sol");
var dns = require("dnssec-oracle/lib/dns.js");
var namehash = require('eth-ens-namehash');
var sha3= require('web3').utils.sha3;
var tld = "xyz";
let ens, algorithm, digest;

function encodeAnchors(anchors) {
  var buf = new Buffer(4096);
  var off = 0;
  for(var anchor of anchors) {
    off = dns.encodeDS(buf, off, anchor);
  }
  return "0x" + buf.toString("hex", 0, off);
}

module.exports = function(deployer, network) {
  var test = (network == "test");
  var anchors = [
    {
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 19036,
      algorithm: 8,
      digestType: 2,
      digest: new Buffer("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5", "hex")
    },
    {
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 20326,
      algorithm: 8,
      digestType: 2,
      digest: new Buffer("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "hex")
    },
  ];
  if(test) {
    anchors.push({
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 5647, // Empty body, flags == 0x0101, algorithm = 253, body = 0x1111
      algorithm: 253,
      digestType: 253,
      digest: new Buffer("", "hex")
    });
  }

  return deployer.deploy(DNSSEC, encodeAnchors(anchors))
    .then(() => deployer.deploy([[ENSImplementation],[dummyalgorithm], [dummydigest]]))
    .then(() => ENSImplementation.deployed().then(_ens => ens = _ens))
    .then(() => deployer.deploy([[rsasha256], [rsasha1], [sha256], [sha1], [nsec3sha1]]))
    .then(() => test?deployer.deploy([[dummyalgorithm], [dummydigest]]):null)
    .then(() => DNSSEC.deployed().then(_dnssec => dnssec = _dnssec))
    .then(() => deployer.deploy(DNSRegistrar, dnssec.address, ens.address, dns.hexEncodeName(tld + "."), namehash.hash(tld)))
    .then(() => DNSRegistrar.deployed().then(_registrar => registrar = _registrar))
    .then(() => ENSImplementation.deployed().then(_ens => _ens.setSubnodeOwner(0, sha3(tld), registrar.address)))
    .then(() => DNSSEC.deployed().then((_dnssec) => {
      tasks = [];

      tasks.push(rsasha1.deployed().then(async function(algorithm) {
        await dnssec.setAlgorithm(5, algorithm.address);
        await dnssec.setAlgorithm(7, algorithm.address);
      }));
      tasks.push(rsasha256.deployed().then((algorithm) => dnssec.setAlgorithm(8, algorithm.address)));
      tasks.push(sha1.deployed().then((digest) => dnssec.setDigest(1, digest.address)));
      tasks.push(sha256.deployed().then((digest) => dnssec.setDigest(2, digest.address)));
      tasks.push(nsec3sha1.deployed().then((digest) => dnssec.setNSEC3Digest(1, digest.address)));
      if(test) {
        tasks.push(dummyalgorithm.deployed().then((algorithm) => dnssec.setAlgorithm(253, algorithm.address)));
        tasks.push(dummyalgorithm.deployed().then((algorithm) => dnssec.setAlgorithm(254, algorithm.address)));
        tasks.push(dummydigest.deployed().then((digest) => dnssec.setDigest(253, digest.address)));
      }
      return Promise.all(tasks);
    }));
};
