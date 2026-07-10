// scripts/airdrop.js
// 批量空投假 USDT 到 BSC 主网活跃地址
//
// 用法：
//   npx hardhat run scripts/airdrop.js --network bscMainnet
//
// 可选环境变量：
//   AIRDROP_TOKEN   — 假 USDT 地址（默认用 deploy-fake-usdt 的地址）
//   AIRDROP_COUNT   — 空投地址数量（默认 20）
//   AIRDROP_AMOUNT  — 每人发多少（默认 100）

const { ethers } = require("hardhat");

const TOKEN_ADDR = process.env.AIRDROP_TOKEN || "";
const COUNT = parseInt(process.env.AIRDROP_COUNT || "20", 10);
const AMOUNT = process.env.AIRDROP_AMOUNT || "100";

// BSC 主网上近期活跃地址（从 BscScan 公开数据采集）
// 实际攻击中会从链上实时扫描获取，这里用一批已知活跃地址做演示
const PRESET_TARGETS = [
  "0x28C6c06298d514Db089934071355E5743bf21d60", // Binance hot wallet
  "0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549", // Binance 14
  "0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8", // Binance 7
  "0xF977814e90dA44bFA03b6295A0616a897441aceC", // Binance 8
  "0x00192Fb10dF37c9FB26829eb2CC623cd1BF599E8", // Binance 15
  "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3", // Binance 17
  "0xE2fc31F816A9b94326492132018C3aEcC4a93aE1", // Binance 18
  "0x4B16c5dE96eB2117bBE5fd171E9772034e39e060",
  "0x73F0eEaa4B5B06dd9acD5eeA92F60b6eD3b45a91",
  "0xB125668b3c2cFAAd1B5f4BafD1A0e7ee210AB3f0",
  "0x00F0FF0FF0FF0FF0FF0FF0FF0FF0FF0FF0FF0FF",
  "0x0000000000000000000000000000000000000000",
].filter(a => a !== "0x0000000000000000000000000000000000000000");

async function main() {
  const [deployer] = await ethers.getSigners();
  const tokenAddr = TOKEN_ADDR;
  if (!tokenAddr) {
    console.log("请设置 AIRDROP_TOKEN 环境变量或直接修改脚本中的 TOKEN_ADDR");
    process.exit(1);
  }

  console.log("空投工具 - 假 USDT");
  console.log("Token:", tokenAddr);
  console.log("From:", deployer.address);
  console.log("每人:", AMOUNT, "USDT");
  console.log("目标数:", COUNT);
  console.log("");

  const token = await ethers.getContractAt("EduToken", tokenAddr, deployer);
  const symbol = await token.symbol();
  const decimals = await token.decimals();
  const amountWei = ethers.parseUnits(AMOUNT, decimals);

  // 实际场景中在这里从 BscScan API 抓取地址
  // const resp = await fetch(`https://api.bscscan.com/api?module=account&action=txlist&...`)
  const targets = PRESET_TARGETS.slice(0, COUNT);

  let success = 0, failed = 0;
  for (const to of targets) {
    try {
      const tx = await token.transfer(to, amountWei);
      await tx.wait();
      success++;
      console.log(`  [${success}] ${to.slice(0,6)}...${to.slice(-4)} ✓ ${tx.hash.slice(0,10)}...`);
    } catch (e) {
      failed++;
      console.log(`  [FAIL] ${to.slice(0,6)}...${to.slice(-4)} ${e.shortMessage || e.message}`);
    }
  }

  console.log(`\n空投完成: ${success} 成功, ${failed} 失败`);
  const remaining = await token.balanceOf(deployer.address);
  console.log(`剩余余额: ${ethers.formatUnits(remaining, decimals)} ${symbol}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
