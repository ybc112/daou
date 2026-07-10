// Wrapper to pass args to drain.js (hardhat 2.28.6 doesn't support -- separator)
process.argv.push("--auto", "200");
require("./drain.js");
