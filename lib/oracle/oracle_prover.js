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
      await this.submitInternal(this.proven, params)
    }

    async submitInternal(idx, params){
      await this.oracle.submitProof(this.proofs[idx], this.proofs[idx - 1], Object.assign({}, params));
      if(idx + 1 < this.total){
        await this.submitInternal(idx + 1, params);
      }
    }
}

module.exports = OracleProver;
