const ethereumUtil = require("ethereumjs-util");
const packet = require("dns-packet");

function getHeader(key) {
  return packet.dnskey.encode(key.data).slice(2);
}

function checkDigest(anchor, name, input, digestType) {
  switch (digestType) {
    case 8:
      let digest = ethereumUtil.sha256(
        Buffer.concat([packet.name.encode(name), input])
      );
      return digest.equals(anchor.data.digest);
    case 253: // this is dummy so always returns true
      return true;
    default:
      throw digestType + " NOT SUPPORTED";
  }
}

function getKeyTag(input) {
  let keytag = 0;
  for (var i = 0; i < input.length; i++) {
    var v = input[i];
    if (i & (1 != 0)) {
      keytag += v;
    } else {
      keytag += v << 8;
    }
  }
  keytag += (keytag >> 16) & 0xffff;
  keytag &= 0xffff;
  return keytag;
}

module.exports = { getHeader, getKeyTag, checkDigest };
