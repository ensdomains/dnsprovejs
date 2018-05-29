const packet = require('dns-packet');

function display(r){
  var header = [r.name, r.ttl, r.class, r.type];
  var data = Object.values(r.data);
  var row = header.concat(data);
  var type;
  row.unshift("//");
  switch(r.type){
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
  row[row.length -1] = row[row.length -1].toString(type);
  return row.join("\t");
}

function buildProofs(results){
  return results.map((result)=>{
    let rrsig = pack(result.rrs, result.sig).toString('hex')
    let name = result.name;
    if(name != '.'){ name = name +  '.'; }
    return new Proof(name, result.sig.data.signature.toString('hex'), rrsig)
  })
}

function pack(rrset, sig) {
  let lengthField = 2;
  const s1 = Object.assign({}, sig.data, {signature: new Buffer(0)});
  s1.signature = new Buffer(0);
  let sigEncoded = packet.rrsig.encode(s1);  
  let sigwire = sigEncoded.slice(lengthField);
  let rrdata  = rawSignatureData(rrset, sig);
  return Buffer.concat([sigwire, rrdata]);
}
  
function rawSignatureData(rrset, sig) {
  let encoded = rrset
    .map((r)=>{
      // https://tools.ietf.org/html/rfc4034#section-6
      // TODO (1, 3, 4)
      const r1 = Object.assign(r, {
        name: r.name.toLowerCase(), // (2)
        ttl: sig.data.originalTTL   // (5)
      });
      return packet.answer.encode(r1);
    }).sort((a,b)=>{
      return a.compare(b);
    })
    return Buffer.concat(encoded);
}

class Proof{
  constructor(name, sig, rrsig) {
    this.name = name;
    this.sig = sig;
    this.rrsig = rrsig;
  }
}

class Result{
  constructor(results) {
    if(results.length >0){
      this.found   = true;
      this.results = results
      this.proofs  = buildProofs(results);
    }
  }

  display(){
    return this.results.map((result)=>{
      let row = [display(result.sig)];
      result.rrs.forEach((r)=>{
        row.push(display(r));
      })
      return row;
    })
  }
}

module.exports = Result;
