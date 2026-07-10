// scripts/tron/seed.js
// 给指定 Router 补充 EDU 流动性（TRON Nile 测试网）
//
// 用法：
//   SEED_ROUTER="Txxx" SEED_TOKEN="Txxx" SEED_AMOUNT="100000" node scripts/tron/seed.js

const { TronWeb } = require("tronweb");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PRIVATE_KEY = process.env.TRON_PRIVATE_KEY || "";
const NILE_RPC = "https://nile.trongrid.io";

async function main() {
  const router = process.env.SEED_ROUTER;
  const token = process.env.SEED_TOKEN;
  const amount = process.env.SEED_AMOUNT || "100000";

  if (!router || !token) {
    console.log("用法：");
    console.log('  SEED_ROUTER="Txxx" SEED_TOKEN="Txxx" SEED_AMOUNT="100000" node scripts/tron/seed.js');
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
  console.log("Router:", router);
  console.log("Amount:", amount, "EDU");

  const tokenContract = await tronWeb.contract().at(token);
  const decimals = await tokenContract.decimals().call();
  const amountWei = BigInt(amount) * (10n ** BigInt(decimals));

  const tx = await tokenContract.transfer(router, TronWeb.toHex(amountWei)).send({
    feeLimit: 100000000,
    from: deployer,
  });
  console.log("Txid:", tx);

  const bal = await tokenContract.balanceOf(router).call();
  console.log("Router EDU 余额:", tronWeb.fromSun(BigInt(String(bal))));
}

main().catch((e) => { console.error(e); process.exit(1); });
