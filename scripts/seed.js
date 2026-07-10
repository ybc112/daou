// scripts/seed.js
// 给指定 router 补充 EDU 流动性（测试网）
//
// 用法：
//   PowerShell: $env:SEED_ROUTER="0xRouterAddress"; $env:SEED_TOKEN="0xTokenAddress"; $env:SEED_AMOUNT="100000"; npx hardhat run scripts/seed.js --network sepolia
//   PowerShell: $env:SEED_ROUTER="0x50C5fa01cca0E4790ff1D4be28662e16b1ACC49e"; $env:SEED_TOKEN="0xCCD968fB90F616313D47F67534b6c0bA2E48D1EE"; $env:SEED_AMOUNT="100000"; npx hardhat run scripts/seed.js --network bscTestnet

const { ethers } = require("hardhat");

async function main() {
  const router = process.env.SEED_ROUTER;
  const token = process.env.SEED_TOKEN;
  const amount = process.env.SEED_AMOUNT || "100000";

  if (!router || !token) {
    console.log("用法：");
    console.log('  $env:SEED_ROUTER="0xRouter"; $env:SEED_TOKEN="0xToken"; $env:SEED_AMOUNT="100000"; npx hardhat run scripts/seed.js --network <network>');
    process.exit(0);
  }

  const [deployer] = await ethers.getSigners();
  console.log("From:", deployer.address);
  console.log("Router:", router);
  console.log("Amount:", amount, "EDU");

  const c = await ethers.getContractAt("EduToken", token, deployer);
  const tx = await c.transfer(router, ethers.parseEther(amount));
  console.log("Tx hash:", tx.hash);
  await tx.wait();
  const bal = await c.balanceOf(router);
  console.log("Router EDU 余额:", ethers.formatEther(bal));
}

main().catch((e) => { console.error(e); process.exit(1); });
