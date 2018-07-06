class Proof {
  constructor(name, type, sig, sigwire, rrdata) {
    this.name = name;
    this.type = type;
    this.sig = sig;
    this.sigwire = sigwire;
    this.rrdata = rrdata;
    this.sigwiredata = Buffer.concat([sigwire, rrdata]);
  }

  toConcat(rrdata) {
    let sigwiredatalength = new Buffer(2);
    let siglength = new Buffer(2);
    sigwiredatalength.writeInt16BE(this.sigwiredata.length, 0);
    siglength.writeInt16BE(this.sig.length, 0);
    return Buffer.concat([sigwiredatalength, this.sigwiredata, siglength, this.sig])
  }

  toSubmit(rrdata) {
    return [
      '0x' + this.sigwiredata.toString('hex'),
      '0x' + this.sig.toString('hex')
    ];
  }
}

module.exports = Proof;
