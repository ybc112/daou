// scripts/tron/deploy.js
// TRON 部署 EduToken + EduSwap（支持主网和 Nile 测试网）
//
// 用法：
//   node scripts/tron/deploy.js                # 默认主网 (约需 200 TRX)
//   node scripts/tron/deploy.js --testnet      # Nile 测试网
//
// 环境变量（.env）：
//   TRON_PRIVATE_KEY=你的私钥

const { TronWeb } = require("tronweb");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PRIVATE_KEY = (process.env.TRON_PRIVATE_KEY || "").replace(/^0x/, "");

const NETWORKS = {
  mainnet: {
    name: "TRON Mainnet",
    fullHost: "https://api.trongrid.io",
    chainId: "728126428",
    explorer: "https://tronscan.org",
    // 主网无质押能量时需燃烧 TRX 换取能量 (~420 SUN/energy)
    // 部署 TRC20 约需 200k+ energy → ~84 TRX，设高一些防止 OUT_OF_ENERGY
    deployFeeLimit: 120_000_000_000,   // 120 TRX per contract deploy
    callFeeLimit: 50_000_000,          // 50 TRX per method call
    minTrx: 200,
  },
  nile: {
    name: "Nile Testnet",
    fullHost: "https://nile.trongrid.io",
    chainId: "3448148188",
    explorer: "https://nile.tronscan.org",
    deployFeeLimit: 3000_000_000,
    callFeeLimit: 40_000_000,
    minTrx: 10,
  },
};

const EduTokenArtifact = require("../../artifacts/contracts/EduToken.sol/EduToken.json");
const EduSwapArtifact = require("../../artifacts/contracts/EduSwap.sol/EduSwap.json");

async function main() {
  const isTestnet = process.argv.includes("--testnet");
  const network = isTestnet ? NETWORKS.nile : NETWORKS.mainnet;

  console.log("═".repeat(60));
  console.log(`  TRON 部署 - ${network.name}`);
  console.log("═".repeat(60));

  if (!PRIVATE_KEY) {
    console.log("错误: 请在 .env 文件中设置 TRON_PRIVATE_KEY");
    process.exit(1);
  }

  const tronWeb = new TronWeb({
    fullHost: network.fullHost,
    privateKey: PRIVATE_KEY,
  });

  const deployer = tronWeb.defaultAddress.base58;
  console.log("部署账户:", deployer);

  const trxBalance = await tronWeb.trx.getBalance(deployer);
  const trxAmount = Number(tronWeb.fromSun(trxBalance));
  console.log("TRX 余额:", trxAmount, "TRX");

  if (trxAmount < network.minTrx) {
    console.log(`⚠ TRX 余额不足 (需要至少 ${network.minTrx} TRX 作为 Gas 费)`);
    console.log(`   当前余额: ${trxAmount} TRX`);
    if (isTestnet) {
      console.log("领取测试币: https://nileex.io/join/getJoinPage");
    } else {
      console.log("请向该地址转入足够 TRX 后再部署");
    }
    process.exit(1);
  }

  // 1. 部署 EduToken
  console.log("\n[1/4] 部署 EduToken...");
  const tokenContract = await tronWeb.contract().new({
    abi: EduTokenArtifact.abi,
    bytecode: EduTokenArtifact.bytecode,
    feeLimit: network.deployFeeLimit,
    callValue: 0,
    userFeePercentage: 100,
    originEnergyLimit: 10_000_000,
    parameters: [TronWeb.toHex(1000000n * 10n ** 18n)],
  });
  const tokenAddr = tronWeb.address.fromHex(tokenContract.address);
  console.log("EduToken 已部署:", tokenAddr);
  console.log("查看: " + network.explorer + "/#/contract/" + tokenAddr);

  // 2. 部署 EduSwap
  console.log("\n[2/4] 部署 EduSwap...");
  const swapContract = await tronWeb.contract().new({
    abi: EduSwapArtifact.abi,
    bytecode: EduSwapArtifact.bytecode,
    feeLimit: network.deployFeeLimit,
    callValue: 0,
    userFeePercentage: 100,
    originEnergyLimit: 10_000_000,
    parameters: ["EduSwap"],
  });
  const swapAddr = tronWeb.address.fromHex(swapContract.address);
  console.log("EduSwap 已部署:", swapAddr);
  console.log("查看: " + network.explorer + "/#/contract/" + swapAddr);

  // 3. 将代币加入白名单
  console.log("\n[3/4] 配置白名单...");
  const swapInstance = await tronWeb.contract().at(swapAddr);
  await swapInstance.addSupportedToken(tokenContract.address).send({
    feeLimit: network.callFeeLimit,
    from: deployer,
  });
  console.log("已将 EduToken 加入 EduSwap 白名单");

  // 4. 给 Router 转代币做流动性
  console.log("\n[4/4] 添加初始流动性...");
  const tokenInstance = await tronWeb.contract().at(tokenAddr);
  const seedAmount = 100000n * 10n ** 18n;
  await tokenInstance.transfer(swapContract.address, TronWeb.toHex(seedAmount)).send({
    feeLimit: network.callFeeLimit,
    from: deployer,
  });
  console.log("已给 Router 转入 100,000 EDU 流动性");

  // 输出结果
  console.log("\n" + "═".repeat(60));
  console.log(`  ${network.name} 部署完成`);
  console.log("═".repeat(60));
  console.log(JSON.stringify({
    network: network.name,
    chainId: network.chainId,
    EduToken_TRC20: tokenAddr,
    EduSwap: swapAddr,
    deployer: deployer,
  }, null, 2));
  console.log("\n请将以上 EduToken_TRC20 和 EduSwap 地址填入 frontend/index.html");
  console.log("CONFIG.chains.tron.token 和 CONFIG.chains.tron.router");
}

main().catch((e) => {
  console.error("部署失败:", e.message || e);
  if (e.response) console.error("Response:", JSON.stringify(e.response));
  process.exit(1);
});
