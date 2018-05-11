var packet = require('dns-packet')
var axios = require('axios')
var util = require('ethereumjs-util');
var Base64 = require('js-base64').Base64;
var SUPPORTED_ALGORITHM = 8;
var SUPPORTED_DIGESTS = 2;
var TRUST_ANCHORS = [
  {
    name: ".",
    type: "DS",
    // ttl: 3600,
    class: "IN",
    // flush: false,
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
  let sigs = await filterRRs(r.answers, 'RRSIG');
  let rrs = await getRRset(r.answers, name, qtype).catch((e)=>{ console.log("**ERROR", e)});
  // console.log('INFO ', qtype, name, r.answers.length, sigs.length, rrs.length);

  let ret;
  // TODO: raise an error if sig nor rrs do not exit.
  for(const sig of sigs){
    ret = await verifyRRSet(sig, rrs).catch((e)=>{ console.log("*** ERROR at verifyRRSet") });
    if(ret){
      ret.push([sig, rrs]);
    }
    // TODO: warn that it failed to verify RRSET
    // console.warn('Failed to verify RRSET');
  }
  return ret;
}

async function verifyRRSet(sig, rrs) {
  // TODO: raise error if !client.supportsAlgorithm(sig.Algorithm)
  let sigHeaderName = sig.name;
  let rrsHeaderRtype = rrs[0].type;
  let sigdata = sig.data;
  let rrsdata = rrs[0].data[0];
  let sets;
  let all_rrsdata = rrs;
  let logs = [];
  let keys = [];
  let signersName = sigdata.signersName;

  if(sigHeaderName == sigdata.signersName && rrsHeaderRtype == 'DNSKEY') {
		keys = rrs;
	}else{
		// Find the keys that signed this RRSET
    sets = await queryWithProof('DNSKEY', sigdata.signersName).catch((e)=>{ console.log("** ERROR at DNSKEY", e,)});;
    if(sets){
      keys = sets[sets.length - 1]
    }else{
      console.log("ERR")
    }
  }

  for(const key of keys){
    // TODO
    // 	if(key.data.algorithm != sig.data.algorithm || key.data.keyTag != sig.data.keyTag || key.name != sig.data.signerName) {
    // 		continue
    // 	}
    // TODO
    // sig.verify(key, rrs)
    if (sig.name == sig.data.signersName) {
      // RRSet is self-signed; look for DS records in parent zones to verify
      sets = await verifyWithDS(key).catch((e)=>{ console.log("** ERROR at verifyWithDS", e,)});
    }
  }
  return sets;
}

function getHeader(key){
  return packet.dnskey.encode(key.data).slice(2);
}

function getDigest(name, input){
  return util.sha256(Buffer.concat([packet.name.encode(name), input]));
}

function getKeyTag(input){
  var keytag = 0;
  for(var i = 0; i < input.length; i++){
    var v = input[i];
    if (i & 1 != 0) {
      keytag += v
    } else {
      keytag += v << 8
    }
  }
  keytag += (keytag >> 16) & 0xFFFF
  keytag &= 0xFFFF
  return keytag;
}

async function verifyWithDS(key) {
  var header = getHeader(key);
  var digest = getDigest(key.name, header);
  var keyTag = getKeyTag(header);
  var matched = TRUST_ANCHORS.filter((anchor)=>{
    return (anchor.name == key.name) &&
           (anchor.data.algorithm == key.data.algorithm) &&
           (anchor.data.keyTag == keyTag) &&
           (anchor.data.digest.toString('hex').toLowerCase() == digest.toString('hex').toLowerCase())
  })
  // TODO: Check supportsDigest(ds.DigestType) {
  if(matched && matched.length > 0){
    return [];
  }

  // Look up the DS record
  sets = await queryWithProof('DS', key.name);
  // TODO: Validate DS records that validate DNSKEY
  // for _, ds := range sets[len(sets)-1].Rrs {
	// 	ds := ds.(*dns.DS)
	// 	if !client.supportsDigest(ds.DigestType) {
	// 		continue
	// 	}
	// 	if strings.ToLower(key.ToDS(ds.DigestType).Digest) == strings.ToLower(ds.Digest) {
	// 		return sets, nil
	// 	}
	// }
  // return nil, fmt.Errorf("Could not find any DS records that validate %s DNSKEY %s (%s/%d)", dns.ClassToString[key.Header().Class], key.Header().Name, dns.AlgorithmToString[key.Algorithm], keytag)
  return sets;
}

async function filterRRs(rrs, qtype){
  return rrs.filter((r)=>{ return r.type == qtype });
}

async function getRRset(rrs, name, qtype){
  return rrs.filter((r)=>{ return r.type == qtype && r.name == name });
}

async function getDNS(buf) {
  let url = 'https://cloudflare-dns.com/dns-query?ct=application/dns-udpwireformat&dns=';
  let response = await axios.get(url + buf.toString('base64'), { responseType:'arraybuffer' })
  let decoded = packet.decode(response.data);
  return decoded
}

function display(r){
  var header = [r.name, r.ttl, r.class, r.type];
  var data = Object.values(r.data);
  var row = header.concat(data);
  row.unshift("//");
  row[row.length -1] = Base64.encode(row[row.length -1].toString('hex'));
  return row.join("\t");
}

function pack(rrset, sig) {
  var sigwire = packet.rrsig.encode(sig.data);
  var rrdata  = rawSignatureData(rrset, sig);
  var concatenated = Buffer.concat([sigwire, rrdata]);
  // this is possibly wrong;
  var sigEncoded = sig.data.signature;
  // var sigEncoded = Base64.encode(sig.data.signature);
  return [concatenated, sigEncoded];
}

function rawSignatureData(rrset, sig) {
  var encoded = rrset
    .map((r)=>{
      // https://tools.ietf.org/html/rfc4034#section-6
      // TODO (1, 3, 4)
      const r1 = Object.assign(r, {
        name: r.name.toLowerCase(), // (2)
        ttl: sig.data.originalTTL   // (5)
      });
      return r1;
    })
    .sort((a,b)=>{ return a.name - b.name })
    .map((r)=>{ 
      var encoder = packet.record(r.type);
      return encoder.encode(r.data);
    })
  return Buffer.concat(encoded);
}

queryWithProof('TXT', '_ens.ethlab.xyz').then((results, error)=>{
  results.forEach((result)=>{ 
    console.log(display(result[0]));
    result[1].forEach((r)=>{
      console.log(display(r));
    })
    var packed = pack(result[1], result[0]).map((p)=>{return p.toString('hex')});
    // debugger;
    packed.unshift(result[0].name);
    console.log(packed);
    console.log("\n");
  })
}).catch((e)=>{
  console.log('error', e);
})
