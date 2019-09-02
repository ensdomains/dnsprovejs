class DnsResult {
  /**
   *
   * @constructor
   * @param {Object} dns_result
   * @param {boolean} dns_result.found - true if the given record exists
   * @param {boolean} dns_result.nsec  - true if the given record does not exist and NSEC/NSEC3 is enabled
   * @param {Array} dns_result.results - an array of SignedSet containing name, signature, and rrs
   * @param {Array} dns_result.proofs  - an array of proofs constructed using results
   * @param {string} dns_result.lastProof - the last proof which you submit into Oracle contruct
   */
  constructor({ found, nsec, results, proofs, lastProof }) {
    this.found = found;
    this.nsec = nsec;
    this.results = results;
    this.proofs = proofs;
    this.lastProof = lastProof;
  }
}

module.exports = DnsResult;
