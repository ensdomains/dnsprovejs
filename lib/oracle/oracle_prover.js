class OracleProver{
    constructor(oracle, total, proven, proofs, owner){
      this.oracle = oracle;
      this.total = total;
      this.proven = proven;
      this.unproven = total - proven;
      this.proofs = proofs;
      this.owner = owner;
    }
    async submit(idx){
      if(typeof(idx) !== 'undefined'){
        await this.submitInternal(idx, false)
      }else{
        await this.submitInternal(this.proven, true)
      }
    }
  
    async submitInternal(idx, recursive){
      await this.oracle.submitProof(this.proofs[idx], this.proofs[idx - 1], {from:this.owner})
      if(recursive && idx + 1 < this.total){
        await this.submitInternal(idx + 1, recursive);
      }
    }
}

module.exports = OracleProver;
