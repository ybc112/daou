// filter-test-accounts.js — 从数据库中过滤掉测试账户
// 运行: node filter-test-accounts.js

const fs = require('fs');
const DB_PATH = process.argv[2] || 'findings-v2.db';

async function main() {
  const SQL = await require('sql.js')();
  const db = new SQL.Database(fs.existsSync(DB_PATH) ? fs.readFileSync(DB_PATH) : new SQL.Database());

  const before = db.exec("SELECT COUNT(*) FROM findings")[0]?.values?.[0]?.[0] || 0;

  // 测试账户特征
  const patterns = [
    '%hardhat%', '%ganache%', '%truffle test%', '%testrpc%',
    '%0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80%',
    '%0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d%',
    '%0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a%',
    '%example%key%', '%demo%key%',
  ];

  let deleted = 0;
  for (const pat of patterns) {
    db.run('DELETE FROM findings WHERE LOWER(context) LIKE ?', [pat]);
    deleted += db.getRowsModified();
  }

  const after = db.exec("SELECT COUNT(*) FROM findings")[0]?.values?.[0]?.[0] || 0;
  console.log(`Before: ${before}, Deleted: ${deleted}, After: ${after}`);

  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  console.log('DB updated');
}
main();
