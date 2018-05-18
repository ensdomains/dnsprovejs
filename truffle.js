module.exports = {
  networks: {
    test: {
      host: "localhost",
      port: 8545,
      network_id: "*",
    },
  },
  solc: {
    optimizer: {
      enabled: true,
      runs: 200
    }
  }
};
