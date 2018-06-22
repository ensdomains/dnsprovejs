const namehash = require('eth-ens-namehash');
const DnsProve  = require('./../lib/dnsprover.js');
const DNSSEC = require("../build/contracts/DNSSEC.json");
const ENSImplementation = require("../build/contracts/ensimplementation.json");
const DNSRegistrar = require("../build/contracts/dnsregistrar.json");
const Web3      = require('web3');
const dns = require("@ensdomains/dnssec-oracle/lib/dns.js");

function updateDOM(element, message, override){
  if(override){
    document.getElementById(element).innerHTML = message;
  }else{
    document.getElementById(element).innerHTML = document.getElementById(element).innerHTML   + '\n' + message;
  }
}

function askOracle(){
  document.getElementById("oracle-output").innerHTML = '';
  let proofs = window.result.proofs;
  proofs.forEach(function(proof){
    let rrdata;
    window.oracle.knownProof(proof).then(function(r){
      updateDOM('oracle-output', proof.name + '\t' + proof.type + '\t' + r)
    });
  })
  updateDOM('oracle-output', 'The address is owned by ' +  window.result.owner)
}

function askEns(input, cb){
  console.log('owner', input, namehash.hash(input));
  window.ens.owner(namehash.hash(input), (error, r)=>{
    console.log('ens', error, r);
    cb(r);
  })
}

function claim(name, proof){
  let encodedProof = '0x' + proof.rrdata.toString('hex');
  window.dnsregistrar.claim(dns.hexEncodeName(name + '.'), encodedProof, {from: web3.eth.defaultAccount}, (error, r)=>{
    console.log('claimed', r);
  });
}

function submitProof(proofs, i){
  let proof = proofs[i]
  window.oracle.knownProof(proof).then(function(r){
    if(r == '0x0000000000000000000000000000000000000000'){
      window.oracle.submitProof(proof, proofs[i-1], {from: web3.eth.defaultAccount}).then(function(r){
        console.log('result', i, r);
        if(i < proofs.length - 1){
          submitProof(proofs, i+1)
        }else{
          askEns(window.input, (r)=>{
            if(r == '0x0000000000000000000000000000000000000000'){
              claim(window.input, proof)
            }
          })  
          updateDOM('oracle-output', 'Click Lookup button to check the latest state');
        }
      });
    }else{
      if(i < proofs.length - 1){
        submitProof(proofs, i+1)
      }else{
        askEns(window.input, (r)=>{
          if(r == '0x0000000000000000000000000000000000000000'){
            claim(window.input, proof)
          }
        })
        updateDOM('oracle-output', 'Click Lookup button to check the latest state');
      }
    }
  });
}

document.addEventListener("DOMContentLoaded", function(event) {
  if (typeof web3 !== 'undefined') {
    // Use the browser's ethereum provider
    var provider = web3.currentProvider
    console.log('Using metamask')
  } else {
    var provider = new Web3.providers.HttpProvider("http://localhost:8545");
    console.log('Using local provider')
  }

  // They are pre web3 1.0 syntax loaded via metamask
  web3.version.getNetwork((error, network)=>{
    const oracleAddress = DNSSEC.networks[network].address;
    const oracleAbi =     DNSSEC.abi;
    const ensAddress = ENSImplementation.networks[network].address;
    const ensAbi = ENSImplementation.abi;
    const dnsregistrarAddress = DNSRegistrar.networks[network].address;
    const dnsregistrarAbi = DNSRegistrar.abi;
    var OracleContract = web3.eth.contract(oracleAbi);
    var ENSContract = web3.eth.contract(ensAbi);
    var DNSRegistrarContract = web3.eth.contract(dnsregistrarAbi);
    window.ens = ENSContract.at(ensAddress);
    window.dnsregistrar = DNSRegistrarContract.at(dnsregistrarAddress);
    window.dnsprove  = new DnsProve(provider);  
    window.oracle = dnsprove.getOracle(oracleAddress)
    window.oldOracle = OracleContract.at(oracleAddress);
    window.ensEvents = ens.allEvents({fromBlock: 0, toBlock: 'latest'});
    window.dnsregistrarEvents = dnsregistrar.allEvents({fromBlock: 0, toBlock: 'latest'});
    window.oracleEvents = oldOracle.allEvents({fromBlock: 0, toBlock: 'latest'});
  })
  
  document.getElementById("lookup-button").onclick = function (){
    document.getElementById("lookup-output").innerHTML = '';
    window.input = document.getElementById("lookup-input").value;
    document.getElementById("lookup-output").innerHTML = window.input;
    dnsprove.lookup('_ens.' + window.input).then(function(r){
      window.result = r
      if(result.found){
        document.getElementById("lookup-output").innerHTML = r.display().map((c)=>{
          return c.join('\n');
        }).join('\n');
        askEns(window.input, (r)=>{
          updateDOM('ens-lookup-output', r || input + ' is not found on ENS', true);
        })
        askOracle()
      }else{
        document.getElementById("lookup-output").innerHTML = 'the entry does not exist on DNS';
      }
    })
  }
  document.getElementById("submit-button").onclick = function (){
    updateDOM('oracle-output', '', true);
    if(!window.result){
      updateDOM('oracle-output', 'Please lookup DNS first');
      return false;
    }
    submitProof(window.result.proofs, 0)
  }
})
