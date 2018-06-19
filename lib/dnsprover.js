require('babel-polyfill');
const Oracle = require('./oracle/oracle');
const Result = require('./dns/result');
const Verifier = require('./dns/verifier');
const OracleProver = require('./oracle/oracle_prover');

class DnsProover{
  constructor(provider) {
    this.provider = provider;
  }

  async lookup(query){
    let result = await Verifier.queryWithProof('TXT', query)
    return new Result(result);
  }

  async prove(query, oracleAddress){
    let result = await this.lookup(query);
    let oracle = await this.getOracle(oracleAddress);
    let i = 0;
    while(i < result.proofs.length){
      let proof = result.proofs[i];
      let proven = await oracle.knownProof(proof);
      if (parseInt(proven) == 0){
        break;
      }
      i++;
    }
    return new OracleProver(oracle, result.proofs.length, i, result.proofs, result.owner);
  }

  getOracle(address){
    return new Oracle(this.provider, address);
  }
}

module.exports = DnsProover;
