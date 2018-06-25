class OracleProver{
    constructor(oracle, total, proven, proofs, owner){
      this.oracle = oracle;
      this.total = total;
      this.proven = proven;
      this.unproven = total - proven;
      this.proofs = proofs;
      this.lastProof = '0x' + proofs[proofs.length -1].rrdata.toString('hex');
      this.owner = owner;
    }

    async submit(params){
      await this.submitInternal(this.proven, true, params)
    }

    async submitOne(idx, params){
      await this.submitInternal(idx, false, params)
    }
  
    async submitInternal(idx, recursive, params){
      await this.oracle.submitProof(this.proofs[idx], this.proofs[idx - 1], Object.assign({}, params));
      if(recursive && idx + 1 < this.total){
        await this.submitInternal(idx + 1, recursive, params);
      }
    }
}

module.exports = OracleProver;
