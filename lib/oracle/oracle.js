const artifact = require('@ensdomains/dnssec-oracle/build/contracts/DNSSECImpl.json');
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
    let result = await this.contract.methods.rrdata(type, name).call(); 
    let inception = parseInt(result[0]);
    let inserted = parseInt(result[1]);
    let hash = result[2];
    let validInception = (inception <= proof.inception);
    let toProve;
    if(proof.rrdata){
      toProve = this.web3.utils.sha3('0x' + proof.rrdata.toString('hex'), {encoding:"hex"}).slice(0,42)
    }

    return({
      inception:inception,
      inserted:inserted,
      hash:hash,
      hashToProve: toProve,
      validInception: validInception,
      matched:(validInception && (hash === toProve))
    });
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

  async deleteProof(type, name, proof, prevProof, params){
    let rrdata = proof.toSubmit(proof);
    let proofdata = '0x' + prevProof.rrdata.toString('hex');
    let res = await this.contract.methods.deleteRRSet(
      types.toType(type),
      hexEncodeName(name),
      rrdata[0],
      rrdata[1],
      proofdata
    ).send(params);
  }

  toProve(proof){
    return this.web3.utils.sha3(proof.rrdata).slice(0,42);
  }

  async getAllProofs(result){
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
    let data = await this.getAllProofs(result);
    await this.contract.methods.submitRRSets(...data).send(params);
  }

  async allProven(result){
    let proven = await this.getProven(result)
    return (proven == result.proofs.length)
  }

  async getProven(result) {
    if (!result.found) return { error: 'dns record not found' };

    let i;
    for(i = result.proofs.length - 1; i >= 0; i--) {
      let proof = result.proofs[i];
      let proven = await this.knownProof(proof);
      if (proven.matched) break;
    }
    return i + 1;
  }
}

module.exports = Oracle;
