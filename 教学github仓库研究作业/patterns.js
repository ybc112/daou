// patterns.js — 私钥/敏感信息检测模式库

module.exports = {
  // Ethereum / BSC / EVM 兼容链私钥
  eth: {
    label: "Ethereum/BSC 私钥",
    severity: "critical",
    // 64 位 hex 私钥，可带 0x 前缀
    regex: /(?:0x)?[a-fA-F0-9]{64}/g,
    // 过滤掉明显是地址的（太常见）
    preFilter: (content) => {
      // 先找 .env, config, secret, key 等关键字附近的匹配
      const lines = content.split("\n");
      const results = [];
      const keyWords = /(private.?key|secret|mnemonic|phrase|pk|PRIVATE|SECRET|MNEMONIC)/i;
      for (let i = 0; i < lines.length; i++) {
        if (keyWords.test(lines[i]) || keyWords.test(lines[i - 1] || "") || keyWords.test(lines[i + 1] || "")) {
          const matches = lines[i].match(/0x[a-fA-F0-9]{64}|[a-fA-F0-9]{64}/g);
          if (matches) {
            for (const m of matches) {
              // 排除全 0、全 f 的测试私钥
              if (/^0{64}$|^f{64}$/i.test(m.replace("0x", ""))) continue;
              results.push({ line: i + 1, key: m, context: lines[i].trim() });
            }
          }
        }
      }
      return results;
    },
  },

  // 助记词（BIP39 12/24 词）
  mnemonic: {
    label: "助记词",
    severity: "critical",
    regex: /\b(?:[a-z]{2,8}\s+){11,23}[a-z]{2,8}\b/gi,
    preFilter: (content) => {
      const results = [];
      const lines = content.split("\n");
      const bipWords = new Set(require("./bip39-wordlist.js"));
      for (let i = 0; i < lines.length; i++) {
        const words = lines[i].toLowerCase().match(/[a-z]{2,8}/gi);
        if (!words || (words.length !== 12 && words.length !== 24)) continue;
        const validCount = words.filter((w) => bipWords.has(w)).length;
        // 90% 以上的词在 BIP39 词表中才算
        if (validCount >= words.length * 0.85) {
          results.push({
            line: i + 1,
            key: words.join(" "),
            context: lines[i].trim().slice(0, 200),
            confidence: Math.round((validCount / words.length) * 100),
          });
        }
      }
      return results;
    },
  },

  // SSH 私钥
  ssh: {
    label: "SSH 私钥",
    severity: "high",
    regex: /-----BEGIN\s+(RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----/gm,
    preFilter: (content) => {
      const results = [];
      const matches = content.match(
        /-----BEGIN\s+(RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----/gm
      );
      if (matches) {
        for (const m of matches) {
          const idx = content.indexOf(m);
          const line = content.slice(0, idx).split("\n").length;
          results.push({
            line,
            key: m.slice(0, 80) + "...",
            context: m.slice(0, 120),
          });
        }
      }
      return results;
    },
  },

  // Bitcoin WIF 私钥
  btc: {
    label: "Bitcoin WIF 私钥",
    severity: "critical",
    regex: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g,
    preFilter: (content) => {
      const results = [];
      const matches = content.match(/[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g);
      if (matches) {
        for (const m of matches) {
          const idx = content.indexOf(m);
          const line = content.slice(0, idx).split("\n").length;
          results.push({ line, key: m, context: content.split("\n")[line - 1]?.trim() || "" });
        }
      }
      return results;
    },
  },

  // 通用 .env / config 中的私钥
  env: {
    label: ".env 配置文件私钥",
    severity: "critical",
    regex: /(?:PRIVATE[_-]?KEY|SECRET|MNEMONIC|PASSPHRASE)\s*=\s*["']?([0-9a-fA-Fx]{64,}|[a-zA-Z0-9+/]{40,})["']?/gi,
    preFilter: (content) => {
      const results = [];
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const m = line.match(
          /(?:PRIVATE[_-]?KEY|SECRET|MNEMONIC|PASSPHRASE|WALLET[_-]?KEY|DEPLOY[_-]?KEY)\s*=\s*["']?([^"'\s]{40,})["']?/i
        );
        if (m) {
          const value = m[1].replace(/['"]/g, "");
          // 排除明显不是私钥的值
          if (/^https?:\/\//i.test(value)) continue;
          if (value.length < 40) continue;
          results.push({
            line: i + 1,
            key: value.slice(0, 20) + "..." + value.slice(-10),
            context: line.trim(),
            varName: m[0].split("=")[0].trim(),
          });
        }
      }
      return results;
    },
  },
};
