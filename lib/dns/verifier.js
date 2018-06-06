require('isomorphic-fetch');
const packet = require('dns-packet');
const Util = require('../util.js');
const getHeader = Util.getHeader;
const getKeyTag = Util.getKeyTag;
const checkDigest = Util.checkDigest;

require('es6-promise').polyfill();
require('isomorphic-fetch');
const SingedSet = require('./signed_set.js');

var SUPPORTED_ALGORITHM = 8;
var SUPPORTED_DIGESTS = 2;
var TRUST_ANCHORS = [
  {
    name: ".",
    type: "DS",
    class: "IN",
    data:{
      keyTag: 19036,
      algorithm: 8,
      digestType: 2,
      digest: new Buffer("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5", "hex")
    }
  },
  {
    name: ".",
    type: "DS",
    // ttl: 3600,
    class: "IN",
    // flush: false,
    data:{
      keyTag: 20326,
      algorithm: 8,
      digestType: 2,      
      digest: new Buffer("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "hex")
    }
  },
  // This is dummy entry for testing
  {
    name: ".",
    type: "DS",
    // ttl: 3600,
    class: "IN",
    // flush: false,
    data:{
      keyTag: 5647,
      algorithm: 253,
      digestType: 253,      
      digest: new Buffer([])
    }
  }
]

// TODO
// function supportsAlgorithm() {}
// function supportsDigest(){}

async function query(qtype, name){
  let buf = packet.encode({
    type: 'query',
    id: 1,
    flags: packet.RECURSION_DESIRED,
    questions: [{
      type: qtype,
      class: 'IN',
      name: name
    }],
    additionals: [{
      type: 'OPT',
      name: '.',
      udpPayloadSize: 4096,
      flags: packet.DNSSEC_OK
    }]
  })
  return  await getDNS(buf);
}
    
async function queryWithProof(qtype, name){
  let r = await query(qtype, name);
  console.log('* queryWithProof', qtype, name, r.answers.length);
  let sigs = await filterRRs(r.answers, 'RRSIG');
  let rrs = await getRRset(r.answers, name, qtype).catch((e)=>{ console.log("**ERROR", e)});
  let ret;
  for(const sig of sigs){
    ret = await verifyRRSet(sig, rrs);
    if(ret){
      ret.push(new SingedSet(name, sig, rrs));
      return ret;
    }
    // TODO: warn that it failed to verify RRSET
  }
  console.warn('Failed to verify RRSET');
}

async function verifyRRSet(sig, rrs) {
  // TODO: raise error if !client.supportsAlgorithm(sig.Algorithm)
  let sigHeaderName = sig.name;
  let rrsHeaderRtype = rrs[0].type;
  let sigdata = sig.data;
  let rrsdata = rrs[0].data[0];
  let keys = [];
  let sets;
  let signersName = sigdata.signersName;

  if(sigHeaderName == sigdata.signersName && rrsHeaderRtype == 'DNSKEY') {
    keys = rrs;
	}else{
    // Find the keys that signed this RRSET
    sets = await queryWithProof('DNSKEY', sigdata.signersName);
    if(sets){
      keys = sets[sets.length - 1].rrs;
    }else{
      console.log("**.* ERR")
    }
  }
  for(const key of keys){
    var header = getHeader(key);
    var keyTag = getKeyTag(header);
    if(key.data.algorithm != sig.data.algorithm || keyTag != sig.data.keyTag || key.name != sig.data.signersName) {
      continue;
    }
    // TODO
    // sig.verify(key, rrs)
    if (sig.name == sig.data.signersName && rrsHeaderRtype == 'DNSKEY') {
      // RRSet is self-signed; look for DS records in parent zones to verify      
      sets = await verifyWithDS(key)
    }
  }
  if(typeof(sets) != 'undefined'){
    return sets;
  }else{
    console.warn('sets undefined')
  }
}


async function verifyWithDS(key) {
  var header = getHeader(key);
  var keyTag = getKeyTag(header);
  var matched = TRUST_ANCHORS.filter((anchor)=>{
    return (anchor.name == key.name) &&
           (anchor.data.algorithm == key.data.algorithm) &&
           (anchor.data.keyTag == keyTag) &&
           (checkDigest(anchor, key.name, header, key.data.digestType || key.data.algorithm))
  })
  // TODO: Check supportsDigest(ds.DigestType) {
  if(matched && matched.length > 0){
    return [];
  }

  // Look up the DS record
  let sets = await queryWithProof('DS', key.name);
  // TODO: Validate DS records that validate DNSKEY
  sets[sets.length-1].rrs.forEach((ds)=>{
    // 	if !client.supportsDigest(ds.DigestType) {
    // 		continue
    // 	}
    if(checkDigest(ds.data.digest, key.name, header, key.data.digestType || key.data.algorithm)){
      return sets;
    }
  })
  return sets;
}

async function filterRRs(rrs, qtype){
  return rrs.filter((r)=>{ return r.type == qtype });
}

async function getRRset(rrs, name, qtype){
  return rrs.filter((r)=>{ return r.type == qtype && r.name == name });
}

async function getDNS(buf) {
  let url = 'https://dns.google.com/experimental?ct=application/dns-udpwireformat&dns=';
  let response = await fetch(url + buf.toString('base64'));
  let buffer;
  if(typeof(response.arrayBuffer) === "function"){
    buffer = await response.arrayBuffer(); // browser builtin
  }else if(typeof(response.buffer) === "function"){
    buffer = await response.buffer(); // node, using isomorphic-fetch
  }else{
    throw("this environment does not have function to support buffer");
  }
  let decoded = packet.decode(Buffer.from(buffer));
  return decoded;
}

module.exports.queryWithProof = queryWithProof;
