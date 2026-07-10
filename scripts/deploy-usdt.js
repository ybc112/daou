const { ethers } = require("hardhat");

// BSC mainnet real USDT
const USDT = "0x55d398326f99059fF775485246999027B3197955";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  // 1. 部署 EduSwap
  const EduSwap = await ethers.getContractFactory("EduSwap");
  const router = await EduSwap.deploy("EduSwap");
  await router.waitForDeployment();
  const routerAddr = await router.getAddress();
  console.log("EduSwap deployed to:", routerAddr);

  // 2. 把真实 USDT 加入支持列表
  await router.addSupportedToken(USDT);
  console.log("Supported USDT on router:", USDT);

  // 输出
  const config = {
    network: "bscMainnet",
    chainId: 56,
    USDT: USDT,
    EduSwap: routerAddr,
  };
  console.log("\n=== Deployed Addresses ===");
  console.log(JSON.stringify(config, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
