#!/usr/bin/env node
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const patterns = require("./patterns.js");

const PORT = process.env.PORT || 3000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const SCAN_INTERVAL = parseInt(process.env.SCAN_INTERVAL || "600") * 1000;
const DB_PATH = path.join(__dirname, "findings.db");

const BASE = "https://api.github.com";
const HEADERS = {
  Accept: "application/vnd.github.v3+json",
  "User-Agent": "github-secret-scanner-edu",
  ...(GITHUB_TOKEN ? { Authorization: "token " + GITHUB_TOKEN } : {}),
};

// ===== SQLite via sql.js =====
let SQL, db;

async function getDB() {
  if (db) return db;
  const initSqlJs = require("sql.js");
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, severity TEXT, repo TEXT, file_path TEXT, file_url TEXT,
    line_num INTEGER, secret_hash TEXT, context TEXT, var_name TEXT,
    confidence TEXT, stars INTEGER, last_pushed TEXT,
    status TEXT DEFAULT 'new', found_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_dedup ON findings(repo, file_path, line_num)");
  db.run("CREATE INDEX IF NOT EXISTS idx_type ON findings(type)");
  db.run("CREATE INDEX IF NOT EXISTS idx_found ON findings(found_at)");
  saveDB();
  return db;
}

function saveDB() {
  if (db) fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function runSQL(sql, params = []) {
  try { db.run(sql, params); saveDB(); return true; } catch (e) { return false; }
}

function queryAll(sql, params = []) {
  try {
    const stmt = db.prepare(sql); stmt.bind(params);
    const rows = []; while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free(); return rows;
  } catch (e) { return []; }
}

function queryOne(sql, params = []) {
  return queryAll(sql, params)[0] || null;
}

// ===== 工具 =====
function hash(s) { return crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 16); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ===== 扫描引擎 =====
const ALERT_KEYWORDS = ["PRIVATE_KEY", "MNEMONIC", "SECRET", "PASSPHRASE", "privateKey", "secretKey", "walletKey"];

const SEARCH_QUERIES = [
  { type: "eth", q: "PRIVATE_KEY=0x language:javascript" },
  { type: "eth", q: "PRIVATE_KEY= extension:env" },
  { type: "eth", q: "PRIVATE_KEY language:python extension:py" },
  { type: "eth", q: "PRIVATE_KEY language:typescript" },
  { type: "eth", q: "PRIVATE_KEY language:go" },
  { type: "eth", q: "PRIVATE_KEY language:rust" },
  { type: "eth", q: '"private key" hex extension:env' },
  { type: "mnemonic", q: "mnemonic= language:javascript" },
  { type: "mnemonic", q: "MNEMONIC= extension:env" },
  { type: "mnemonic", q: "MNEMONIC language:python" },
  { type: "ssh", q: '"BEGIN RSA PRIVATE KEY"' },
  { type: "ssh", q: '"BEGIN OPENSSH PRIVATE KEY"' },
  { type: "ssh", q: "id_rsa extension:key" },
  { type: "env", q: "PRIVATE_KEY= extension:env" },
  { type: "env", q: "SECRET_KEY= extension:env" },
  { type: "env", q: "MNEMONIC= extension:env" },
];

let scanRunning = false;
let scanStats = { total: 0, new: 0, lastScan: null, currentQuery: "" };

async function githubSearch(query, page = 1) {
  const q = new URLSearchParams({ q: query, per_page: "30", page: String(page), sort: "indexed", order: "desc" });
  const url = BASE + "/search/code?" + q.toString();
  const resp = await fetch(url, { headers: HEADERS });
  const remaining = resp.headers.get("x-ratelimit-remaining");
  const reset = resp.headers.get("x-ratelimit-reset");
  if (resp.status === 403 && remaining === "0") {
    const wait = Math.max(0, (Number(reset) - Date.now() / 1000) | 0) + 2;
    console.log("Rate limited, waiting " + wait + "s");
    await sleep(wait * 1000);
    return githubSearch(query, page);
  }
  if (resp.status === 422 || resp.status === 404) return { total_count: 0, items: [] };
  if (!resp.ok) throw new Error("API " + resp.status);
  return resp.json();
}

async function fetchFile(url) {
  const resp = await fetch(url, { headers: HEADERS });
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.content ? Buffer.from(data.content, "base64").toString("utf-8") : null;
}

async function runScan() {
  if (scanRunning) return;
  scanRunning = true;
  let newCount = 0;

  try {
    for (const item of SEARCH_QUERIES) {
      const pattern = patterns[item.type];
      if (!pattern) continue;
      scanStats.currentQuery = item.q;

      for (let page = 1; page <= 3; page++) {
        try {
          const data = await githubSearch(item.q, page);
          if (!data.items || data.items.length === 0) break;

          for (const fi of data.items) {
            await sleep(150);
            const content = await fetchFile(fi.url);
            if (!content) continue;

            let matches = [];
            if (pattern.preFilter) {
              const result = pattern.preFilter(content);
              if (result) matches = Array.isArray(result) ? result : [];
            }

            for (const match of matches) {
              if (!match.key || match.key.length < 20) continue;
              const ctxLower = (match.context || "").toLowerCase();
              const hasAlert = ALERT_KEYWORDS.some((kw) => ctxLower.includes(kw.toLowerCase()));
              const conf = match.confidence || (hasAlert ? "high" : "medium");

              runSQL(
                "INSERT OR IGNORE INTO findings (type,severity,repo,file_path,file_url,line_num,secret_hash,context,var_name,confidence,stars,last_pushed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [pattern.label, pattern.severity, fi.repository.full_name, fi.path, fi.html_url, match.line,
                 hash(match.key), (match.context || "").slice(0, 500), match.varName || "",
                 conf, fi.repository.stargazers_count || 0, fi.repository.pushed_at || ""]
              );
              newCount++;
            }
          }
          if (data.items.length < 30) break;
          await sleep(3000);
        } catch (e) { break; }
      }
    }
  } catch (e) { console.error("Scan error:", e.message); }

  scanStats.new = newCount;
  scanStats.total = queryOne("SELECT COUNT(*) as c FROM findings")?.c || 0;
  scanStats.lastScan = new Date().toISOString();
  scanRunning = false;
  console.log("Scan done: " + newCount + " new, total: " + scanStats.total);
}

// ===== HTML 面板 =====
function serveHTML(type) {
  const where = type ? "type = ?" : "1=1";
  const params = type ? [type] : [];
  const findings = queryAll("SELECT * FROM findings WHERE " + where + " ORDER BY id DESC LIMIT 200", params);
  const byType = queryAll("SELECT type, COUNT(*) as c FROM findings GROUP BY type");
  const total = queryOne("SELECT COUNT(*) as c FROM findings")?.c || 0;

  const rows = findings.map((f) => {
    const sevBadge = f.severity === "critical"
      ? '<span class="b crit">' + f.severity + "</span>"
      : '<span class="b high">' + f.severity + "</span>";
    const ctx = String(f.context || f.secret_hash || "...").replace(/</g, "&lt;").slice(0, 80);
    return "<tr><td>" + sevBadge + "</td><td>" + f.type + "</td><td><a href=\"https://github.com/" + f.repo + "\" target=\"_blank\">" + f.repo + "</a></td><td title=\"" + f.file_path + "\">" + f.file_path.slice(-50) + "</td><td>" + (f.line_num || "-") + "</td><td title=\"" + (f.context || "").replace(/"/g, "&quot;").slice(0, 100) + "\">" + ctx + "</td><td>" + (f.confidence || "medium") + "</td><td>" + (f.stars || 0) + "</td><td>" + (f.found_at || "").slice(0, 16) + "</td></tr>";
  }).join("");

  const typeBtns = byType.map((t) =>
    "<a href=\"/?type=" + encodeURIComponent(t.type) + "\" style=\"margin:0 8px;color:#4f46e5\">" + t.type + " (" + t.c + ")</a>"
  ).join("");

  return "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\"/><title>GitHub 私钥泄露监控</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,\"PingFang SC\",monospace;background:#0a0a0f;color:#e0e4ec;padding:20px}h1{font-size:22px;margin-bottom:4px}.sub{color:#6b7280;font-size:13px;margin-bottom:20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}.stat{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:14px 18px}.stat .label{font-size:11px;color:#7f889b}.stat .value{font-size:24px;font-weight:700;margin-top:4px;color:#ef4444}.bar{display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap}.btn{padding:8px 16px;border-radius:7px;background:#4f46e5;color:white;border:none;cursor:pointer;font-size:13px;text-decoration:none}.btn:hover{opacity:.85}.btn:disabled{opacity:.5;cursor:wait}table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}th{color:#7f889b;font-weight:600;padding:10px 12px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.08);position:sticky;top:0;background:#0a0a0f}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04)}tr:hover td{background:rgba(255,255,255,0.02)}a{color:#6aa7ff;text-decoration:none}a:hover{text-decoration:underline}.b{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700}.b.crit{background:rgba(239,68,68,0.15);color:#ef4444}.b.high{background:rgba(240,185,11,0.15);color:#f7b955}</style></head><body><h1>GitHub 私钥泄露监控</h1><div class=\"sub\">自动扫描开发者不小心提交的私钥/助记词 · 教学研究用途</div><div class=\"stats\"><div class=\"stat\"><div class=\"label\">总发现</div><div class=\"value\">" + total + "</div></div><div class=\"stat\"><div class=\"label\">本次新增</div><div class=\"value\" style=\"color:#22c55e\">" + scanStats.new + "</div></div><div class=\"stat\"><div class=\"label\">扫描状态</div><div class=\"value\" style=\"font-size:14px;color:#6b7280\">" + (scanRunning ? "运行中" : "空闲") + "</div></div><div class=\"stat\"><div class=\"label\">上次扫描</div><div class=\"value\" style=\"font-size:14px\">" + (scanStats.lastScan ? scanStats.lastScan.slice(11, 19) : "-") + "</div></div><div class=\"stat\"><div class=\"label\">API Token</div><div class=\"value\" style=\"font-size:14px\">" + (GITHUB_TOKEN ? "已设置" : "无(10次/分)") + "</div></div></div><div class=\"bar\"><a href=\"/scan?secret=edu2026\" class=\"btn\" " + (scanRunning ? "disabled" : "") + ">" + (scanRunning ? "扫描中..." : "触发扫描") + "</a><a href=\"/\" class=\"btn\" style=\"background:#374151\">全部</a>" + typeBtns + "<span style=\"font-size:12px;color:#6b7280;margin-left:auto\">间隔:" + (SCAN_INTERVAL / 1000) + "s | 查询:" + scanStats.currentQuery + "</span></div><table><thead><tr><th>严重度</th><th>类型</th><th>仓库</th><th>文件</th><th>行</th><th>内容</th><th>置信度</th><th>⭐</th><th>发现时间</th></tr></thead><tbody>" + (rows || "<tr><td colspan=\"9\" style=\"text-align:center;color:#6b7280;padding:40px\">暂无数据，等待扫描...</td></tr>") + "</tbody></table></body></html>";
}

// ===== 启动 =====
(async () => {
  await getDB();
  console.log("DB ready");

  const server = http.createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    const url = new URL(req.url, "http://localhost");

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      const type = url.searchParams.get("type") || "";
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(serveHTML(type));
      return;
    }

    if (req.method === "GET" && url.pathname === "/scan" && url.searchParams.get("secret") === "edu2026") {
      runScan();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, msg: "扫描已触发" }));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/stats") {
      const total = queryOne("SELECT COUNT(*) as c FROM findings")?.c || 0;
      const byType = queryAll("SELECT type, COUNT(*) as c FROM findings GROUP BY type");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ total, byType, scanStats }));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/findings") {
      const type = url.searchParams.get("type") || "";
      const where = type ? "type = ?" : "1=1";
      const rows = queryAll("SELECT * FROM findings WHERE " + where + " ORDER BY id DESC LIMIT 200", type ? [type] : []);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(rows));
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") { res.writeHead(200); res.end("OK"); return; }
    res.writeHead(404); res.end("not found");
  });

  server.listen(PORT, "0.0.0.0", () => {
    console.log("Server on port " + PORT);
    // 首次扫描
    setTimeout(() => runScan(), 3000);
    setInterval(() => runScan(), SCAN_INTERVAL);
  });
})();
