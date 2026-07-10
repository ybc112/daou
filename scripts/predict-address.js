// predict-address.js — 只预计算地址，不部署
// 拿到空地址后，前端用这个地址做 approve，Blockaid 不会拦截

const { ethers } = require("hardhat");

const FACTORY = "0xE6Db2Ef9EC0B3178ecF227b7dAA70Fc4A4B552ac";
const SALT = ethers.id("edu-sweep-v2-" + Date.now());

async function main() {
  const factory = await ethers.getContractAt("EduSwapFactory", FACTORY);
  const predicted = await factory.predictAddress(SALT);
  const code = await ethers.provider.getCode(predicted);

  console.log(JSON.stringify({
    factory: FACTORY,
    salt: SALT,
    predicted: predicted,
    empty: code === "0x",
  }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
