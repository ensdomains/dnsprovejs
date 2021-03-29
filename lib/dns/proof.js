class Proof {
  /**
   * @constructor
   * @param {string} name
   * @param {string} type
   * @param {string} sig
   * @param {number} inception
   * @param {string} sigwire
   * @param {string} rrdata
   */
  constructor(name, type, sig, inception, sigwire, rrdata) {
    this.name = name;
    this.type = type;
    this.sig = sig;
    this.inception = inception;
    this.sigwire = sigwire;
    this.rrdata = rrdata;
    this.sigwiredata = Buffer.concat([sigwire, rrdata]);
  }

  toConcat() {
    let sigwiredatalength = new Buffer(2);
    let siglength = new Buffer(2);
    sigwiredatalength.writeInt16BE(this.sigwiredata.length, 0);
    siglength.writeInt16BE(this.sig.length, 0);
    return Buffer.concat([
      sigwiredatalength,
      this.sigwiredata,
      siglength,
      this.sig
    ]);
  }

  /**
   * toSubmit returns an array consisting of hex string of sigwiredata (concatinatd string of sigwire and rrdata) and its signature
   * @returns {array} data
   */
  toSubmit() {
    return [
      '0x' + this.sigwiredata.toString('hex'),
      '0x' + this.sig.toString('hex')
    ];
  }
}

module.exports = Proof;
