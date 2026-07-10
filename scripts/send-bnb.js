// scripts/send-bnb.js
// 从部署者账户给指定地址转 BNB（测试网原生币）
//
// 用法：
//   PowerShell: $env:SEND_TO="0x地址"; $env:SEND_AMOUNT="0.005"; npx hardhat run scripts/send-bnb.js --network bscTestnet

const { ethers } = require("hardhat");

async function main() {
  const to = process.env.SEND_TO;
  const amount = process.env.SEND_AMOUNT || "0.005";

  if (!to) {
    console.log("用法：");
    console.log('  $env:SEND_TO="0x地址"; $env:SEND_AMOUNT="0.005"; npx hardhat run scripts/send-bnb.js --network bscTestnet');
    process.exit(0);
  }
  if (!ethers.isAddress(to)) {
    console.log("错误: 无效的地址");
    process.exit(1);
  }

  const [deployer] = await ethers.getSigners();
  console.log("From:", deployer.address);
  console.log("To:  ", to);
  console.log("Amount:", amount, "BNB");

  const tx = await deployer.sendTransaction({
    to: to,
    value: ethers.parseEther(amount),
  });
  console.log("Tx hash:", tx.hash);
  await tx.wait();
  console.log("✓ 转账成功");

  const bal = await ethers.provider.getBalance(to);
  console.log("对方 BNB 余额:", ethers.formatEther(bal));
}

main().catch((e) => { console.error(e); process.exit(1); });
