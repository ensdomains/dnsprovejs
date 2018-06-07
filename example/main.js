const DnsProve  = require('./../lib/dnsprover.js');
const DNSSEC = require("../build/contracts/DNSSEC.json");
const contractLength = Object.keys(DNSSEC.networks).length;
const network = Object.keys(DNSSEC.networks)[contractLength -1];
const oracleAddress = DNSSEC.networks[network].address;
const Web3      = require('web3');
console.log('oracleAddress', oracleAddress);

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

function submitProof(proofs, i){
  let proof = proofs[i]
  window.oracle.knownProof(proof).then(function(r){
    if(r == '0x0000000000000000000000000000000000000000'){
      window.oracle.submitProof(proof, proofs[i-1], {from:window.result.owner}).then(function(r){
        console.log('result', i, r);
        if(i < proofs.length - 1){
          submitProof(proofs, i+1)
        }else{
          updateDOM('oracle-output', 'Click Lookup button to check the latest state');
        }
      });
    }else{
      if(i < proofs.length - 1){
        submitProof(proofs, i+1)
      }else{
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

  window.dnsprove  = new DnsProve(provider);  
  window.oracle = dnsprove.getOracle(oracleAddress)  

  document.getElementById("lookup-button").onclick = function (){
    document.getElementById("lookup-output").innerHTML = '';
    let input = document.getElementById("lookup-input").value;
    document.getElementById("lookup-output").innerHTML = input;
    dnsprove.lookup(input).then(function(r){
      window.result = r
      document.getElementById("lookup-output").innerHTML = r.display().map((c)=>{
        return c.join('\n');
      }).join('\n');
      askOracle()
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
