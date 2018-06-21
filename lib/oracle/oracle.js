/// this has no address nor network info
const dns = require("@ensdomains/dnssec-oracle/lib/dns.js");
const artifact = require("@ensdomains/dnssec-oracle/build/contracts/DNSSEC.json");
/// this has all the info
const Web3 = require('web3');
const abi = artifact.abi;

class Oracle{
  constructor(provider, address) {
    this.provider = provider
    this.address = address
    this.web3 = new Web3(provider);
    this.contract = new this.web3.eth.Contract(abi, address)   
  }

  async knownProof(proof){
    let name = dns.hexEncodeName(proof.name);
    let type =  dns['TYPE_' + proof.type];
    return (await this.contract.methods.rrdata(type, name).call())[2]
  }

  async submitProof(proof, prevProof, params){
    let rrdata = proof.toSubmit(proof);
    if(!prevProof){
      prevProof = await this.contract.methods.anchors().call();
      console.log('ANCHOR PROOF', prevProof);
    }else{
      prevProof = '0x' + prevProof.rrdata.toString('hex');
    }

    rrdata.push(prevProof);
    console.log('input', rrdata.join(' '))
    var tx = await this.contract.methods.submitRRSet(...rrdata).send(params);
    console.log('output',tx.events['RRSetUpdated'].raw.topics.join(' '))
    return true;
  }
}

module.exports = Oracle;
