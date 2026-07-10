// scripts/tron/faucet.js
// TRON 测试币水龙头：从部署者账户给指定地址转 EDU 测试币
//
// 用法：
//   $env:FAUCET_TO="Txxx" node scripts/tron/faucet.js
//   FAUCET_TO="Txxx" FAUCET_AMOUNT="1000" node scripts/tron/faucet.js

const TronWeb = require("tronweb");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PRIVATE_KEY = process.env.TRON_PRIVATE_KEY || "";
const NILE_RPC = "https://nile.trongrid.io";

// === 部署后替换为你的实际合约地址 ===
const EDUTOKEN = "TJrG9nepkQBDNmvzauMehCkPq2CUrx5pBT"; // EduToken 地址 (Base58)

async function main() {
  const to = process.env.FAUCET_TO;
  const amount = process.env.FAUCET_AMOUNT || "100";

  if (!to) {
    console.log("用法：");
    console.log('  PowerShell: $env:FAUCET_TO="Txxx"; $env:FAUCET_AMOUNT="1000"; node scripts/tron/faucet.js');
    console.log('  Bash:       FAUCET_TO="Txxx" FAUCET_AMOUNT="1000" node scripts/tron/faucet.js');
    process.exit(0);
  }

  if (!PRIVATE_KEY) {
    console.log("错误: 请在 .env 文件中设置 TRON_PRIVATE_KEY");
    process.exit(1);
  }

  const tronWeb = new TronWeb({
    fullHost: NILE_RPC,
    privateKey: PRIVATE_KEY,
  });
  const deployer = tronWeb.defaultAddress.base58;

  console.log("From:  ", deployer);
  console.log("To:    ", to);
  console.log("Amount:", amount, "EDU");

  const token = await tronWeb.contract().at(EDUTOKEN);
  const decimals = await token.decimals().call();
  const amountWei = BigInt(amount) * (10n ** BigInt(decimals));

  const tx = await token.transfer(to, TronWeb.toHex(amountWei)).send({
    feeLimit: 100000000,
    from: deployer,
  });
  console.log("Txid:", tx);
  console.log("✓ 转账成功");

  const bal = await token.balanceOf(to).call();
  console.log("对方 EDU 余额:", tronWeb.fromSun(BigInt(String(bal))));
}

main().catch((e) => { console.error(e); process.exit(1); });
