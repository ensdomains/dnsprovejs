require('idempotent-babel-polyfill');
const Oracle = require("./oracle/oracle");
const Result = require("./dns/result");
const Verifier = require("./dns/verifier");

class DnsProver {
  constructor(provider) {
    this.provider = provider;
  }

  /**
   * lookup takes DNS record type and name and returns `DnsResult` object.
   *
   * @param {string} type - eg: TXT
   * @param {string} query - eg: _ens.yourdomain.xyz
   * @returns {Object} DnsResult - contains list of results retrieved from DNS record and proofs which are constructed from the record and used to submit into DNSSEC Oracle
   */
  async lookup(type, query) {
    let result = await Verifier.queryWithProof(type, query);
    console.log('***lookup', {result})
    return new Result(result);
  }

  /**
   * getOracle returns Oracle object
   *
   * @param {string} address - DNSSEC Oracle contract address
   * @returns {Object} Oracle - allows you to call DNSSEC oracle functions
   *
   */
  getOracle(address) {
    return new Oracle(this.provider, address);
  }
}

module.exports = DnsProver;
