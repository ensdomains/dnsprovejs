class Oracle{
  constructor(provider, address) {
    this.provider = provider
    this.address = address
  }

  knownProof(){
    return true;
  }

  submitProof(){
    return true;
  }
}

module.exports = Oracle;
