#!/usr/bin/env node
// scanner.js — GitHub 私钥泄露扫描工具（教学用）
//
// 用法:
//   node scanner.js                    # 交互式
//   node scanner.js --type eth         # 只扫以太坊私钥
//   node scanner.js --type all         # 扫所有类型
//   node scanner.js --query "PRIVATE_KEY" --pages 3  # 自定义搜索
//
// 需要 GitHub Token（设置环境变量 GITHUB_TOKEN 可提高限速）
// 无 Token: 10次/分钟  |  有 Token: 30次/分钟

const patterns = require("./patterns.js");

// ========== 配置 ==========
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const BASE = "https://api.github.com";
const HEADERS = {
  "Accept": "application/vnd.github.v3+json",
  "User-Agent": "github-secret-scanner-education",
  ...(GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {}),
};

// GitHub Code Search 查询模板
const SEARCH_QUERIES = {
  eth: [
    'PRIVATE_KEY=0x language:javascript',
    'PRIVATE_KEY= language:dotenv',
    '"private key" hex extension:env',
    'PRIVATE_KEY language:solidity',
    'PRIVATE_KEY= language:typescript',
    'PRIVATE_KEY language:python extension:py',
  ],
  mnemonic: [
    'mnemonic= language:javascript',
    'mnemonic: language:yaml',
    '"mnemonic phrase" extension:env',
    'MNEMONIC= language:dotenv',
    'secret phrase extension:txt',
  ],
  ssh: [
    '"BEGIN RSA PRIVATE KEY" language:text',
    '"BEGIN OPENSSH PRIVATE KEY" language:text',
    'id_rsa extension:key',
    '"BEGIN EC PRIVATE KEY" language:text',
  ],
  btc: [
    'bitcoin private key extension:txt',
    'WIF private key import',
    'wallet import format language:python',
  ],
  env: [
    'PRIVATE_KEY= extension:env',
    'SECRET_KEY= extension:env',
    'MNEMONIC= extension:env',
    '.env PRIVATE_KEY language:javascript',
  ],
};

// 要检查的关键词上下文
const ALERT_KEYWORDS = [
  "PRIVATE_KEY", "MNEMONIC", "SECRET", "PASSPHRASE",
  "privateKey", "secretKey", "walletKey",
  "不要提交", "敏感信息", "private key", "secret key",
];

// ========== 工具函数 ==========

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function githubSearch(query, page = 1) {
  const params = new URLSearchParams({
    q: query,
    per_page: "30",
    page: String(page),
    sort: "indexed",
    order: "desc",
  });
  const url = `${BASE}/search/code?${params}`;

  const resp = await fetch(url, { headers: HEADERS });
  const rateRemaining = resp.headers.get("x-ratelimit-remaining");
  const rateReset = resp.headers.get("x-ratelimit-reset");

  if (resp.status === 403 && rateRemaining === "0") {
    const resetIn = Math.max(0, (Number(rateReset) - Date.now() / 1000) | 0);
    console.log(`  ⏳ API 限流，等待 ${resetIn}s ...`);
    await sleep((resetIn + 2) * 1000);
    return githubSearch(query, page);
  }

  if (resp.status === 422) {
    return { total_count: 0, items: [] };
  }

  if (!resp.ok) {
    throw new Error(`GitHub API error ${resp.status}: ${await resp.text()}`);
  }

  return resp.json();
}

async function fetchFile(url) {
  const resp = await fetch(url, { headers: HEADERS });
  if (!resp.ok) return null;
  const data = await resp.json();
  // GitHub 返回 base64 编码的内容
  if (data.content) {
    return Buffer.from(data.content, "base64").toString("utf-8");
  }
  return null;
}

function extractRepo(url) {
  const m = url.match(/github\.com\/([^/]+\/[^/]+)/);
  return m ? m[1] : url;
}

// ========== 核心扫描逻辑 ==========

async function scanType(type, options = {}) {
  const queries = SEARCH_QUERIES[type] || [];
  const maxPages = options.pages || 2;
  const pattern = patterns[type];
  const findings = [];
  const seenFiles = new Set();

  console.log(`\n${"=".repeat(60)}`);
  console.log(`  🔍 扫描类型: ${pattern.label}`);
  console.log(`${"=".repeat(60)}`);

  for (const query of queries) {
    console.log(`  📡 搜索: "${query}"`);
    for (let page = 1; page <= maxPages; page++) {
      try {
        const data = await githubSearch(query, page);
        if (!data.items || data.items.length === 0) break;

        console.log(
          `    第 ${page} 页 | 命中 ${data.items.length} 个文件 | 总计 ${data.total_count}`
        );

        for (const item of data.items) {
          const fileKey = `${item.repository.full_name}/${item.path}`;
          if (seenFiles.has(fileKey)) continue;
          seenFiles.add(fileKey);

          // 获取文件内容
          await sleep(300); // 避免太快触发限流
          const content = await fetchFile(item.url);
          if (!content) continue;

          // 用对应 pattern 过滤
          if (pattern.preFilter) {
            const matches = pattern.preFilter(content);
            for (const match of matches) {
              // 额外检查：附近有没有敏感关键词
              const contextLower = (match.context || "").toLowerCase();
              const hasAlert = ALERT_KEYWORDS.some((kw) =>
                contextLower.includes(kw.toLowerCase())
              );

              findings.push({
                type: pattern.label,
                severity: pattern.severity,
                repo: item.repository.full_name,
                file: item.path,
                url: item.html_url,
                line: match.line,
                key: match.key,
                context: match.context?.slice(0, 200) || "",
                varName: match.varName || "",
                confidence: match.confidence || (hasAlert ? "high" : "medium"),
                stars: item.repository.stargazers_count || 0,
                lastPushed: item.repository.pushed_at || "",
              });
            }
          }
        }

        if (data.items.length < 30) break;
        await sleep(2000); // 翻页间隔
      } catch (e) {
        console.log(`    ⚠ ${e.message}`);
        break;
      }
    }
  }

  return findings;
}

// ========== 输出 ==========

function printFindings(findings) {
  if (findings.length === 0) {
    console.log("\n  ✅ 未发现泄露。");
    return;
  }

  // 按严重程度分组
  const critical = findings.filter((f) => f.severity === "critical");
  const high = findings.filter((f) => f.severity === "high");

  console.log(`\n${"=".repeat(60)}`);
  console.log(`  📊 扫描结果`);
  console.log(`${"=".repeat(60)}`);
  console.log(`  Critical: ${critical.length}  |  High: ${high.length}  |  总计: ${findings.length}`);
  console.log();

  // 输出详情
  for (const f of findings) {
    const icon = f.severity === "critical" ? "🔴" : "🟡";
    console.log(`${icon} [${f.type}] ${f.repo}`);
    console.log(`   文件: ${f.file}:${f.line}`);
    console.log(`   链接: ${f.url}`);
    console.log(`   泄露: ${f.key}`);
    if (f.varName) console.log(`   变量: ${f.varName}`);
    console.log(`   置信度: ${f.confidence}  |  ⭐ ${f.stars}`);
    console.log();
  }

  // 导出 JSON
  const outFile = `scan-results-${Date.now()}.json`;
  require("fs").writeFileSync(outFile, JSON.stringify(findings, null, 2));
  console.log(`  📁 详细结果已保存: ${outFile}`);
}

// ========== 交互模式 ==========

function showBanner() {
  console.log(`
╔══════════════════════════════════════════════════════╗
║    GitHub 私钥泄露扫描工具 (教学用途)               ║
║    原理: 利用 GitHub Code Search API 搜索           ║
║    开发者不小心提交到公开仓库的私钥/助记词          ║
╚══════════════════════════════════════════════════════╝
`);
}

function showMenu() {
  console.log("请选择扫描类型:");
  console.log("  1. 以太坊/BSC 私钥 (0x...64位hex)");
  console.log("  2. 助记词 (12/24词 BIP39)");
  console.log("  3. SSH 私钥");
  console.log("  4. Bitcoin WIF 私钥");
  console.log("  5. .env 配置文件私钥");
  console.log("  6. 全部扫描");
  console.log("  0. 退出");
}

// ========== 入口 ==========

async function main() {
  showBanner();

  if (!GITHUB_TOKEN) {
    console.log(
      "  ⚠ 未设置 GITHUB_TOKEN，API 限速为 10次/分钟"
    );
    console.log(
      "  💡 设置方法: export GITHUB_TOKEN=ghp_xxxxx\n"
    );
  }

  const args = process.argv.slice(2);
  const typeArg = args.find((a) => a === "--type") ? args[args.indexOf("--type") + 1] : null;
  const pagesArg = args.find((a) => a === "--pages") ? parseInt(args[args.indexOf("--pages") + 1]) : 2;
  const queryArg = args.find((a) => a === "--query") ? args[args.indexOf("--query") + 1] : null;

  // 命令行模式
  if (typeArg || queryArg) {
    let allFindings = [];

    if (queryArg) {
      // 自定义搜索
      console.log(`  🔍 自定义搜索: "${queryArg}"`);
      const data = await githubSearch(queryArg, 1);
      console.log(`  找到 ${data.total_count} 个结果`);
      return;
    }

    if (typeArg === "all") {
      for (const t of Object.keys(SEARCH_QUERIES)) {
        const findings = await scanType(t, { pages: pagesArg });
        allFindings.push(...findings);
      }
    } else if (SEARCH_QUERIES[typeArg]) {
      allFindings = await scanType(typeArg, { pages: pagesArg });
    }

    printFindings(allFindings);
    return;
  }

  // 交互模式
  const readline = require("readline").createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  showMenu();
  readline.question("\n> ", async (choice) => {
    readline.close();
    const typeMap = {
      "1": "eth",
      "2": "mnemonic",
      "3": "ssh",
      "4": "btc",
      "5": "env",
      "6": "all",
    };

    const type = typeMap[choice];
    if (!type) {
      console.log("已退出。");
      return;
    }

    let allFindings = [];
    if (type === "all") {
      for (const t of Object.keys(SEARCH_QUERIES)) {
        const findings = await scanType(t, { pages: 2 });
        allFindings.push(...findings);
      }
    } else {
      allFindings = await scanType(type, { pages: 2 });
    }

    printFindings(allFindings);
  });
}

main().catch((e) => {
  console.error("Error:", e.message);
  process.exit(1);
});
