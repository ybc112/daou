const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  // 1. 部署教学代币
  const Token = await ethers.getContractFactory("EduToken");
  const token = await Token.deploy(ethers.parseEther("1000000"));
  await token.waitForDeployment();
  const tokenAddr = await token.getAddress();
  console.log("EduToken deployed to:", tokenAddr);

  // 2. 部署 EduSwap 路由
  const EduSwap = await ethers.getContractFactory("EduSwap");
  const router = await EduSwap.deploy("EduSwap");
  await router.waitForDeployment();
  const routerAddr = await router.getAddress();
  console.log("EduSwap deployed to:", routerAddr);

  // 3. 把代币加入白名单
  await router.listToken(tokenAddr);
  console.log("Listed EduToken on router");

  // 4. 给部署者/owner 发一些代币，方便测试
  await token.transfer(routerAddr, ethers.parseEther("100000"));
  console.log("Seeded router with 100,000 EDU");

  // 输出 JSON 方便前端复制
  const config = {
    network: (await ethers.provider.getNetwork()).name,
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    EduToken: tokenAddr,
    EduSwap: routerAddr,
  };
  console.log("\n=== Deployed Addresses ===");
  console.log(JSON.stringify(config, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
