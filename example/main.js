const DnsProve = require('./../lib/dnsprover.js');
const Web3      = require('web3');
const provider = new Web3.providers.HttpProvider("http://localhost:8545");
const MyContract = require("../build/contracts/DNSSEC.json");
const network = Object.keys(MyContract.networks)[0];
const address = MyContract.networks[network].address;

const dnsprove  = new DnsProve(provider);
dnsprove.lookup('_ens.matoken.xyz').then(console.log)
