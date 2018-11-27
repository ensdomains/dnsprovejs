const artifact = require('@ensdomains/dnssec-oracle/build/contracts/DNSSECImpl.json');
const Web3 = require('web3');
const abi = artifact.abi;
const packet = require('dns-packet');
const types = require('dns-packet/types');
const OracleProof = require('./oracle_proof');
function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

class Oracle {
  /**
   * 
   * @param {*} provider 
   * @param {*} address 
   */
  constructor(provider, address) {
    this.provider = provider;
    this.address = address;
    this.web3 = new Web3(provider);
    this.contract = new this.web3.eth.Contract(abi, address);
  }

  /**
   * kownProof 
   * @param {Object} proof - takes DNS record 
   * @returns {Object} oracle_proof - contains list of results retrieved from DNS record and proofs  
   */
  async knownProof(proof) {
    let name = hexEncodeName(proof.name);
    let type = types.toType(proof.type);
    let result = await this.contract.methods.rrdata(type, name).call(); 
    let inception = result[0];
    let inserted = result[1];
    let hash = result[2];
    let validInception = (inception <= proof.inception);
    let toProve;
    if(proof.rrdata){
      toProve = this.web3.utils.sha3('0x' + proof.rrdata.toString('hex'), {encoding:"hex"}).slice(0,42)
    }

    return new OracleProof({
      inception:inception,
      inserted:inserted,
      hash:hash,
      hashToProve: toProve,
      validInception: validInception,
      matched:(validInception && (hash === toProve))
    })
  }

  /**
   * submitProof submits a proof to Oracle contract. If `prevProof` is `null`, the oracle contract uses hard-coded root anchor proof to validate the validity of the proof given. `params` is used to pass any params to be sent to transaction, such as `{from:address}`.
   * @param {Object} proof
   * @param {Object} prevProof
   * @param {Object} params - from, gas, gasPrice, etc
   * @returns {boolean} success - returns true unless transaction fails
   */
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

  /**
   * deleteProof deletes a proof
   * @param {string} type - eg: TXT
   * @param {string} name - eg: _ens.matoken.xyz
   * @param {string} proof
   * @param {string} prevProof
   * @param {Object} params - from, gas, gasPrice, etc
   */
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

  /**
   * getAllProofs returns all the proofs needs to be submitted into DNSSEC Oracle. It traverses from the leaf of the chain of proof to check if proof in DNSSEC Oracle and the one from DNS record matches with valid inception value. This function is used so that it can pass the necessary proof to `dnsregistrar.proveAndClaim` function.
   * @param {Object} result
   * @returns {string} data
   * @returns {Object} prevProof
   */
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

  /**
   * submitAll submits all required proofs into the DNSSEC oracle as one transaction in a batch.
   * @param {Object} result
   * @param {Object} params - from, gas, gasPrice, etc
   */
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
