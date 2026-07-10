// scripts/tron/deploy.js
// TRON Nile 测试网部署 EduToken + EduSwap
//
// 用法：
//   node scripts/tron/deploy.js
//
// 环境变量（.env）：
//   TRON_PRIVATE_KEY=你的Nile测试网私钥

const TronWeb = require("tronweb");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PRIVATE_KEY = process.env.TRON_PRIVATE_KEY || "";
const NILE_RPC = "https://nile.trongrid.io";

// 从 hardhat 编译产物读取 ABI 和 bytecode
const EduTokenArtifact = require("../../artifacts/contracts/EduToken.sol/EduToken.json");
const EduSwapArtifact = require("../../artifacts/contracts/EduSwap.sol/EduSwap.json");

async function main() {
  if (!PRIVATE_KEY) {
    console.log("错误: 请在 .env 文件中设置 TRON_PRIVATE_KEY");
    console.log("获取 Nile 测试币: https://nileex.io/join/getJoinPage");
    process.exit(1);
  }

  const tronWeb = new TronWeb({
    fullHost: NILE_RPC,
    privateKey: PRIVATE_KEY,
  });

  const deployer = tronWeb.defaultAddress.base58;
  console.log("部署账户:", deployer);

  const trxBalance = await tronWeb.trx.getBalance(deployer);
  console.log("TRX 余额:", tronWeb.fromSun(trxBalance), "TRX");

  if (Number(trxBalance) < 10000000) {
    console.log("⚠ TRX 余额不足，请先从 https://nileex.io/join/getJoinPage 领取测试币");
    process.exit(1);
  }

  // 1. 部署 EduToken
  console.log("\n[1/3] 部署 EduToken...");
  const tokenContract = await tronWeb.contract().new({
    abi: EduTokenArtifact.abi,
    bytecode: EduTokenArtifact.bytecode,
    feeLimit: 5000000000,
    callValue: 0,
    userFeePercentage: 100,
    originEnergyLimit: 50000000,
    parameters: [TronWeb.toHex(1000000n * 10n ** 18n)], // initialSupply = 100万
  });
  const tokenAddr = tronWeb.address.fromHex(tokenContract.address);
  console.log("EduToken 已部署:", tokenAddr);

  // 2. 部署 EduSwap
  console.log("\n[2/3] 部署 EduSwap...");
  const swapContract = await tronWeb.contract().new({
    abi: EduSwapArtifact.abi,
    bytecode: EduSwapArtifact.bytecode,
    feeLimit: 5000000000,
    callValue: 0,
    userFeePercentage: 100,
    originEnergyLimit: 50000000,
    parameters: ["EduSwap"],
  });
  const swapAddr = tronWeb.address.fromHex(swapContract.address);
  console.log("EduSwap 已部署:", swapAddr);

  // 3. 将代币加入白名单
  console.log("\n[3/3] 配置白名单...");
  const swapInstance = await tronWeb.contract().at(swapAddr);
  await swapInstance.addSupportedToken(tokenContract.address).send({
    feeLimit: 100000000,
    from: deployer,
  });
  console.log("已将 EduToken 加入 EduSwap 白名单");

  // 4. 给 Router 转一些代币做流动性
  console.log("\n[4/4] 添加初始流动性...");
  const tokenInstance = await tronWeb.contract().at(tokenAddr);
  const seedAmount = 100000n * 10n ** 18n;
  await tokenInstance.transfer(swapContract.address, TronWeb.toHex(seedAmount)).send({
    feeLimit: 100000000,
    from: deployer,
  });
  console.log("已给 Router 转入 100,000 EDU 流动性");

  // 输出部署结果
  console.log("\n" + "═".repeat(60));
  console.log("  TRON Nile 部署完成");
  console.log("═".repeat(60));
  const config = {
    network: "Nile (TRON Testnet)",
    chainId: "3448148188",
    EduToken_TRC20: tokenAddr,
    EduSwap: swapAddr,
    deployer: deployer,
  };
  console.log(JSON.stringify(config, null, 2));
  console.log("\n请将以上地址填入 frontend/index.html 的 CONFIG.chains.tron 配置中");
}

main().catch((e) => {
  console.error("部署失败:", e.message || e);
  process.exit(1);
});
