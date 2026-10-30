const testProvider = require("ganache").provider({ logging: { quiet: true } });

module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*",
    },
    test: {
      provider: () => testProvider,
      network_id: "*",
    },
  },
  compilers: {
    solc: { version: "0.8.20" },
  },
};
