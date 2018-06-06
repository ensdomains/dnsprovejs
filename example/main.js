const DnsProve = require('./../lib/dnsprover.js');
const Web3      = require('web3');
const provider = new Web3.providers.HttpProvider("http://localhost:8545");
const MyContract = require("../build/contracts/DNSSEC.json");
const network = Object.keys(MyContract.networks)[0];
const address = MyContract.networks[network].address;
const dnsprove  = new DnsProve(provider);

document.addEventListener("DOMContentLoaded", function(event) {
  document.getElementById("lookup-button").onclick = function (a,b){
    let input = document.getElementById("lookup-input").value;
    console.log('input', input)
    document.getElementById("lookup-output").innerHTML = input;
    dnsprove.lookup(input).then(function(r){
      document.getElementById("lookup-output").innerHTML = r.display().map((c)=>{return c.join('\n');}).join('\n');
    })
    return false;
  }
})
