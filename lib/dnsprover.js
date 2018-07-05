require("babel-polyfill");
const Oracle = require("./oracle/oracle");
const Result = require("./dns/result");
const Verifier = require("./dns/verifier");

class DnsProover {
  constructor(provider) {
    this.provider = provider;
  }

  async lookup(type, query) {
    let result = await Verifier.queryWithProof(type, query);
    return new Result(result);
  }

  getOracle(address) {
    return new Oracle(this.provider, address);
  }
}

module.exports = DnsProover;
