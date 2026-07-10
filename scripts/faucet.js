// scripts/faucet.js
// 从部署者账户给指定地址转 EDU 测试币
//
// 用法：
//   $env:FAUCET_TO="0xAbC..."; $env:FAUCET_AMOUNT="1000"; npx hardhat run scripts/faucet.js --network bscTestnet

const { ethers } = require("hardhat");

const EDUTOKEN = "0xCCD968fB90F616313D47F67534b6c0bA2E48D1EE";

async function main() {
  const to = process.env.FAUCET_TO;
  const amount = process.env.FAUCET_AMOUNT || "100";

  if (!to) {
    console.log("用法：");
    console.log('  PowerShell: $env:FAUCET_TO="0x你的地址"; $env:FAUCET_AMOUNT="1000"; npx hardhat run scripts/faucet.js --network bscTestnet');
    console.log('  CMD:        set FAUCET_TO=0x你的地址 && set FAUCET_AMOUNT=1000 && npx hardhat run scripts/faucet.js --network bscTestnet');
    process.exit(0);
  }
  if (!ethers.isAddress(to)) {
    console.log("错误: 无效的地址");
    process.exit(1);
  }

  const [deployer] = await ethers.getSigners();
  console.log("From:", deployer.address);
  console.log("To:  ", to);
  console.log("Amount:", amount, "EDU");

  const token = await ethers.getContractAt("EduToken", EDUTOKEN, deployer);
  const tx = await token.transfer(to, ethers.parseEther(amount));
  console.log("Tx hash:", tx.hash);
  await tx.wait();
  console.log("✓ 转账成功");

  const bal = await token.balanceOf(to);
  console.log("对方 EDU 余额:", ethers.formatEther(bal));
}

main().catch((e) => { console.error(e); process.exit(1); });
