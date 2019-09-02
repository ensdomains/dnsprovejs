// // Not requiring dummy algo and digest contracts here cause the following error when running tests
// // 'Error: Could not find artifacts for dnssec-oracle/contracts/DummyAlgorithm.sol from any sources'
var dummyalgorithm    = artifacts.require("@ensdomains/dnssec-oracle/DummyAlgorithm.sol");
var dummydigest       = artifacts.require("@ensdomains/dnssec-oracle/DummyDigest.sol");
var _DNSSECInterface  = artifacts.require("@ensdomains/dnssec-oracle/DNSSEC.sol");
var DNSSEC            = artifacts.require("@ensdomains/dnssec-oracle/DNSSECImpl.sol");
var Rsasha1           = artifacts.require("@ensdomains/dnssec-oracle/RSASHA1Algorithm.sol");
var Rsasha256         = artifacts.require("@ensdomains/dnssec-oracle/RSASHA256Algorithm.sol");
var Sha1              = artifacts.require("@ensdomains/dnssec-oracle/SHA1Digest.sol");
var Sha256            = artifacts.require("@ensdomains/dnssec-oracle/SHA256Digest.sol");
var Nsec3sha1         = artifacts.require("@ensdomains/dnssec-oracle/SHA1NSEC3Digest.sol");
var DNSRegistrar      = artifacts.require("@ensdomains/dnsregistrar/DNSRegistrar.sol");
var ENSRegistry       = artifacts.require("@ensdomains/ens/ENSRegistry.sol");

const packet = require('dns-packet');
const dnsAnchors = require("@ensdomains/dnssec-oracle/lib/anchors.js");

var sha3     = require('web3').utils.sha3;
var tld = "xyz";

function hexEncodeName(name){
  return '0x' + packet.name.encode(name).toString('hex');
}

module.exports = async function(deployer) {
  let anchors = dnsAnchors.realEntries;

  await deployer.deploy(DNSSEC, dnsAnchors.encode(anchors));
  await deployer.deploy(ENSRegistry);
  await deployer.deploy(Rsasha256);
  await deployer.deploy(Rsasha1);
  await deployer.deploy(Sha256);
  await deployer.deploy(Sha1);
  await deployer.deploy(Nsec3sha1);

  const ens = await ENSRegistry.deployed();
  const dnssec = await DNSSEC.deployed();
  await deployer.deploy(DNSRegistrar, dnssec.address, ens.address);
  const registrar = await DNSRegistrar.deployed();
  const rsasha1 = await Rsasha1.deployed();
  await ens.setSubnodeOwner('0x', sha3(tld), registrar.address);
  await dnssec.setAlgorithm(5, rsasha1.address);
  await dnssec.setAlgorithm(7, rsasha1.address);
  const rsasha256 = await Rsasha256.deployed();
  await dnssec.setAlgorithm(8, rsasha256.address);
  const sha1 = await Sha1.deployed();
  await dnssec.setDigest(1, sha1.address);
  const sha256 = await Sha256.deployed();
  await dnssec.setDigest(2, sha256.address);
  const nsec3sha1 = await Nsec3sha1.deployed();
  await dnssec.setNSEC3Digest(1, nsec3sha1.address);
};
