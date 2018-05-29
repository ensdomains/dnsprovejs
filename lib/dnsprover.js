const Oracle = require('./oracle/oracle');
const Result = require('./dns/result');
const Verifier = require('./dns/verifier');
const query = require('./dns/query');
class DnsProover{
  constructor(provider) {
    this.provider = provider;
    // this.verifier = new Verifier(query)
  }

  async lookup(query){
    let result = await Verifier.queryWithProof('TXT', query)
    return new Result(result);
  }

  getOracle(address){
    return new Oracle(this.provider, address);
  }
}

module.exports = DnsProover;
