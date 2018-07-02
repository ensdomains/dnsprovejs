const dns = require("@ensdomains/dnssec-oracle/lib/dns.js");
const artifact = require("@ensdomains/dnssec-oracle/build/contracts/DNSSEC.json");
const Web3 = require('web3');
const OracleProver = require('./oracle_prover');
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
    }else{
      prevProof = '0x' + prevProof.rrdata.toString('hex');
    }

    rrdata.push(prevProof);
    await this.contract.methods.submitRRSet(...rrdata).send(params);
    return true;
  }

  async submit(result, params){
    let prover = await this.getProver(result);
    await prover.submit(params);
  }

  async getProver(result){
    if(!result.found) return { error:'dns record not found' };

    let i = 0;
    while(i < result.proofs.length){
      let proof = result.proofs[i];
      let proven = await this.knownProof(proof);
      if (parseInt(proven) == 0){
        break;
      }
      i++;
    }
    return new OracleProver(this, result.proofs.length, i, result.proofs);
  }
}

module.exports = Oracle;
