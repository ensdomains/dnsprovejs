class Proof {
  constructor(name, type, sig, sigwire, rrdata) {
    this.name = name;
    this.type = type;
    this.sig = sig;
    this.sigwire = sigwire;
    this.rrdata = rrdata;
  }

  toSubmit(rrdata) {
    return [
      '0x' + Buffer.concat([this.sigwire, this.rrdata]).toString('hex'),
      '0x' + this.sig.toString('hex')
    ];
  }
}

module.exports = Proof;
