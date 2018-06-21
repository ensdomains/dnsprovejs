// Not requiring dummy algo and digest contracts here cause the following error when running tests
// 'Error: Could not find artifacts for dnssec-oracle/contracts/DummyAlgorithm.sol from any sources'
var dummyalgorithm    = artifacts.require("@ensdomains/dnssec-oracle/contracts/DummyAlgorithm.sol");
var dummydigest       = artifacts.require("@ensdomains/dnssec-oracle/contracts/DummyDigest.sol");
var DNSSEC            = artifacts.require("@ensdomains/dnssec-oracle/contracts/DNSSEC.sol");
var rsasha1           = artifacts.require("@ensdomains/dnssec-oracle/contracts/RSASHA1Algorithm.sol");
var rsasha256         = artifacts.require("@ensdomains/dnssec-oracle/contracts/RSASHA256Algorithm.sol");
var sha1              = artifacts.require("@ensdomains/dnssec-oracle/contracts/SHA1Digest.sol");
var sha256            = artifacts.require("@ensdomains/dnssec-oracle/contracts/SHA256Digest.sol");
var nsec3sha1         = artifacts.require("@ensdomains/dnssec-oracle/contracts/SHA1NSEC3Digest.sol");
var ENSImplementation = artifacts.require("dnsregistrar/contracts/ensimplementation.sol");
var DNSRegistrar      = artifacts.require("dnsregistrar/contracts/dnsregistrar.sol");
var dns      = require("@ensdomains/dnssec-oracle/lib/dns.js");
var namehash = require('eth-ens-namehash');
var sha3     = require('web3').utils.sha3;
var tld = "xyz";
let ens, algorithm, digest;

module.exports = function(deployer, network) {
  var test = (network == "test");
  var anchors = dns.anchors;
  return deployer.deploy(DNSSEC, dns.encodeAnchors(anchors))
    .then(() => deployer.deploy([[ENSImplementation], [rsasha256], [rsasha1], [sha256], [sha1], [nsec3sha1]]))
    .then(() => ENSImplementation.deployed().then(_ens => ens = _ens))
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
      return Promise.all(tasks);
    }));
};
