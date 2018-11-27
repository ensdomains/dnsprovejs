class OracleProof{
    /**
     * @constructor
     * @param {Object} proof
     * @param {number} proof.inception - time (the time the signature was generated) stored in DNSSEC oracle
     * @param {number} proof.inserted - the time the record was inserted into DNSSEC oracle
     * @param {string} proof.hash - hash of proof stored in DNSSEC oracle
     * @param {string} proof.hashToProve - hash of proof constructed from DNS record
     * @param {boolean} proof.validInception - returns true if inception in DNSSEC oracle is older than the one from DNS record.
     * @param {boolean} proof.matched - returns true if inception is valid and hash is matched
     */
    constructor({inception, inserted, hash, hashToProve, validInception, matched}){
      this.inception = inception
      this.inserted = inserted
      this.hash = hash
      this.hashToProve = hashToProve
      this.validInception = validInception
      this.matched = matched
    }
  }
  module.exports = OracleProof;