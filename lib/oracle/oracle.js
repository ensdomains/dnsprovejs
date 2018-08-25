const artifact = require('@ensdomains/dnssec-oracle/build/contracts/DNSSEC.json');
const Web3 = require('web3');
const abi = artifact.abi;
const packet = require('dns-packet');
const types = require('dns-packet/types');

function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

class Oracle {
  constructor(provider, address) {
    this.provider = provider;
    this.address = address;
    this.web3 = new Web3(provider);
    this.contract = new this.web3.eth.Contract(abi, address);
  }

  async knownProof(proof) {
    let name = hexEncodeName(proof.name);
    let type = types.toType(proof.type);
    return (await this.contract.methods.rrdata(type, name).call())[2];
  }

  async submitProof(proof, prevProof, params) {
    let rrdata = proof.toSubmit(proof);
    if (!prevProof) {
      prevProof = await this.contract.methods.anchors().call();
    } else {
      prevProof = '0x' + prevProof.rrdata.toString('hex');
    }

    rrdata.push(prevProof);
    await this.contract.methods.submitRRSet(...rrdata).send(params);
    return true;
  }

  async getAllProof(result){
    let proofs = result.proofs;
    let proven = await this.getProven(result);
    let rrdata = [];
    let prevProof;
    for (var i = proven; i < proofs.length; i++) {
      rrdata.push(proofs[i].toConcat());
    }
    if (proven == 0) {
      prevProof = await this.contract.methods.anchors().call();
    } else {
      prevProof = '0x' + proofs[proven - 1].rrdata.toString('hex');
    }
    let data = '0x' + Buffer.concat(rrdata).toString('hex');
    return [data, prevProof]
  }

  async submitAll(result, params) {
    let data = await this.getAllProof(result);
    await this.contract.methods.submitRRSets(...data).send(params);
  }

  async getProven(result) {
    if (!result.found) return { error: 'dns record not found' };

    let i = 0;
    while (i < result.proofs.length) {
      let proof = result.proofs[i];
      let proven = await this.knownProof(proof);
      if (parseInt(proven) == 0) {
        break;
      }
      i++;
    }
    return i;
  }
}

module.exports = Oracle;
