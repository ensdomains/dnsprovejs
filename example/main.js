const DnsProve = require('./../lib/dnsprover.js');
const Web3      = require('web3');
const provider = new Web3.providers.HttpProvider("http://localhost:8545");
const MyContract = require("../build/contracts/DNSSEC.json");
const contractLength = Object.keys(MyContract.networks).length;
const network = Object.keys(MyContract.networks)[contractLength -1];
const oracleAddress = MyContract.networks[network].address;
const Web3      = require('web3');
console.log('oracleAddress', oracleAddress);

function askOracle(){
  document.getElementById("oracle-output").innerHTML = '';
  let proofs = window.result.proofs;
  proofs.forEach(function(proof){
    let rrdata;
    window.oracle.knownProof(proof).then(function(r){
      console.log('r', r)
      document.getElementById("oracle-output").innerHTML = document.getElementById("oracle-output").innerHTML   + '\n' + proof.name + '\t' + proof.type + '\t' + r;
    });
  })
  document.getElementById("oracle-output").innerHTML = document.getElementById("oracle-output").innerHTML  + '\n' + 'The address is owned by ' +  window.result.owner
}

function submitProof(proofs, i){
  let proof = proofs[i]
  window.oracle.knownProof(proof).then(function(r){
    console.log('r', r)
  });
  window.oracle.knownProof(proof).then(function(r){
    console.log('r', r)
    if(r == '0x0000000000000000000000000000000000000000'){
      window.oracle.submitProof(proof, proofs[i-1], {from:window.result.owner}).then(function(r){
        console.log('result', i, r);
        if(i < proofs.length - 1){
          submitProof(proofs, i+1)
        }else{
          console.log('end')
          document.getElementById("oracle-output").innerHTML = 'Click Lookup button to check the latest state'
        }
      });
    }else{
      if(i < proofs.length - 1){
        submitProof(proofs, i+1)
      }else{
        document.getElementById("oracle-output").innerHTML = 'Click Lookup button to check the latest state'
        console.log('end')
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
    console.log('No web3? You should consider trying MetaMask!')
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
    if(!window.result){
      document.getElementById("oracle-output").innerHTML = 'Please lookup DNS first'
      return false;
    }
    submitProof(window.result.proofs, 0)
  }
})
