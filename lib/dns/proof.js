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
    let sigwiredatalength = this.sigwiredata.toString('hex').length / 2;
    let siglength = this.sig.toString('hex').length / 2;
    let prefixlengh = 4;
    let buf = Buffer.alloc(sigwiredatalength + siglength + prefixlengh);
    buf.writeUInt16BE(sigwiredatalength, 0);
    buf.write(this.sigwiredata.toString('hex'), 2, sigwiredatalength, 'hex');
    buf.writeUInt16BE(siglength, sigwiredatalength + 2);
    buf.write(
      this.sig.toString('hex'),
      sigwiredatalength + prefixlengh,
      siglength,
      'hex'
    );
    return buf;
  }

  toSubmit(rrdata) {
    return [
      '0x' + this.sigwiredata.toString('hex'),
      '0x' + this.sig.toString('hex')
    ];
  }
}

module.exports = Proof;
