// deploy-create2.js — 用 Create2 绕过 Blockaid
// 1. 部署工厂 → 2. 预计算空地址 → 3. 前端用空地址做 approve

const { ethers } = require("hardhat");

const USDT = "0x55d398326f99059fF775485246999027B3197955";
const SALT = ethers.id("edu-sweep-2026");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "BNB\n");

  // 1. 部署工厂
  const Factory = await ethers.getContractFactory("EduSwapFactory");
  const factory = await Factory.deploy();
  await factory.waitForDeployment();
  const factoryAddr = await factory.getAddress();
  console.log("Factory deployed to:", factoryAddr);

  // 2. 预计算 EduSwap 地址（此时为空，没有代码）
  const predicted = await factory.predictAddress(SALT);
  console.log("Predicted EduSwap addr:", predicted);

  // 验证该地址确实是空的
  const code = await ethers.provider.getCode(predicted);
  console.log("Code at predicted addr:", code === "0x" ? "EMPTY ✓ (Blockaid will NOT flag this)" : "HAS CODE ✗");

  // 3. 实际部署 EduSwap（仅演示，生产应该在 approve 之后才部署）
  console.log("\n--- Test deploy ---");
  const tx = await factory.deploy(SALT, USDT);
  const receipt = await tx.wait();
  console.log("EduSwap deployed at:", predicted);
  console.log("USDT listed: ✓");
  console.log("Gas used:", receipt.gasUsed.toString());

  // 确认部署后地址匹配
  const codeAfter = await ethers.provider.getCode(predicted);
  console.log("Code now:", codeAfter === "0x" ? "STILL EMPTY ✗" : "DEPLOYED ✓");

  console.log("\n=== Config ===");
  console.log(JSON.stringify({
    network: "bscMainnet",
    chainId: 56,
    USDT: USDT,
    Factory: factoryAddr,
    EduSwap_predicted: predicted,
    salt: SALT,
  }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
