// var Migrations = artifacts.require("./dnssec-oracle/contracts/Migrations.sol");
var Migrations = artifacts.require("./Migrations.sol");

module.exports = function(deployer) {
  deployer.deploy(Migrations);
};
