const packet = require('dns-packet');
const Proof = require('./proof');
const DnsResult = require('./dns_result');

function display(r) {
  var header = [r.name, r.ttl, r.class, r.type];
  var data = Object.values(r.data);
  var row = header.concat(data);
  var type;
  row.unshift('//');
  switch (r.type) {
    case 'DNSKEY':
      type = 'base64';
      break;
    case 'RRSIG':
      type = 'base64';
      break;
    case 'DS':
      type = 'hex';
      break;
    default:
      break;
  }
  row[row.length - 1] = row[row.length - 1].toString(type);
  return row.join('\t');
}

function buildProofs(results) {
  return results.map(result => {
    let [sigwire, rrdata] = pack(result.rrs, result.sig);
    let name = result.name;
    return new Proof(
      name,
      result.rrs[0].type,
      result.sig.data.signature,
      result.sig.data.inception,
      sigwire,
      rrdata
    );
  });
}

function pack(rrset, sig) {
  let lengthField = 2;
  const s1 = Object.assign({}, sig.data, { signature: new Buffer(0) });
  s1.signature = new Buffer(0);
  let sigEncoded = packet.rrsig.encode(s1);
  let sigwire = sigEncoded.slice(lengthField);
  let rrdata = rawSignatureData(rrset, sig);
  return [sigwire, rrdata];
}

function rawSignatureData(rrset, sig) {
  let encoded = rrset
    .map(r => {
      // https://tools.ietf.org/html/rfc4034#section-6
      const r1 = Object.assign(r, {
        name: r.name.toLowerCase(), // (2)
        ttl: sig.data.originalTTL // (5)
      });
      return packet.answer.encode(r1);
    })
    .sort((a, b) => {
      return a.compare(b);
    });
  return Buffer.concat(encoded);
}

class Result {
  constructor(results) {
    let found, nsec, proofs, lastProof;
    found = false;
    nsec = false;
    if (results && results.length > 0) {
      results = results;
      proofs = buildProofs(results);
      lastProof = '0x' + proofs[proofs.length - 1].rrdata.toString('hex');
      let lastResult = results[results.length - 1];
      let lastResultType;
      if (lastResult.rrs[0]) {
        lastResultType = lastResult.rrs[0].type;
      }
      if (lastResultType == 'NSEC' || lastResultType == 'NSEC3') {
        nsec = true;
      } else {
        found = true;
      }
    }
    return new DnsResult({ found, nsec, results, proofs, lastProof });
  }

  display() {
    return this.results.map(result => {
      let row = [display(result.sig)];
      result.rrs.forEach(r => {
        row.push(display(r));
      });
      return row;
    });
  }
}

module.exports = Result;
