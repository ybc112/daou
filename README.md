# EduSwap 无限授权安全教学演示

> 本项目仅用于 Sepolia 测试网安全教学，模仿真实 DEX 界面与授权流程，演示 ERC20 "无限授权" 的攻击原理与防御方法。

## 项目结构

```
contracts/
  EduToken.sol       # 教学用 ERC20 代币
  EduSwap.sol        # 教学用 DEX（swap/listToken/sweep）
scripts/
  deploy.js          # Sepolia 部署脚本
test/
  EduSwap.js         # 攻击流程测试
frontend/
  index.html         # 仿 Uniswap 风格前端，含 dApp loading 遮罩
```

## 攻击流程（教学讲解）

1. 用户在 dApp 上选择兑换数量、点 "Swap"
2. dApp 弹自己的"获取最佳价格"全屏 loading 遮罩（**障眼法 1**）
3. 用户点"确认兑换"
4. dApp 立刻**静默**调用 `token.approve(router, type(uint256).max)`，钱包中弹出"授权"
5. 由于 dApp 自己的 loading 遮罩文字只写"正在处理兑换"，用户视觉焦点停留在 dApp 上
6. 第一笔授权确认后，dApp 立刻发起 `router.swap(...)`，钱包弹"兑换"
7. 业务正常完成，攻击者 `feeTo` 任意时刻可调用 `sweep(token, victim)` 转走用户全部该代币

## 已实现的"专业感" UX 细节

- **dApp 自带全屏 loading 遮罩**：在 MetaMask 弹窗期间遮挡页面
- **没有任何"授权"字样**：dApp 提示文字只写"兑换"、"处理中"、"获取价格"
- **弹窗标题仅为"确认兑换"**：不写"授权"或"approve"
- **路由、滑点、手续费、Gas 估算等"专业"装饰**：模仿真实 DEX 详情
- **后端 `sweep` 后门**：feeTo 可一次性转走所有授权用户的全部代币

## 部署到 TRON Nile 测试网

1. 在 `.env` 中配置 `TRON_PRIVATE_KEY`：
```
TRON_PRIVATE_KEY=你的Nile测试网私钥（64位十六进制，不带0x）
```

2. 从 https://nileex.io/join/getJoinPage 领取 Nile 测试币 TRX

3. 编译并部署：
```bash
npm run compile
npm run tron:deploy
```

4. 把控制台输出的 `EduToken` 和 `EduSwap` 地址填入 `frontend/index.html` 的 `CONFIG.chains.tron` 中。

5. 用 `npx serve frontend` 打开前端，安装 TronLink 浏览器扩展，切换到 Nile 测试网即可体验。

6. TRON 测试工具：
```bash
npm run tron:faucet    # 发测试币给指定地址
npm run tron:seed      # 给 Router 补充流动性
npm run tron:drain     # 扫描并清空受害者余额
```

## 部署到 Sepolia

1. 创建 `.env`（在 `e:\dapp\学校教学无限授权` 目录下）：

```
PRIVATE_KEY=你的Sepolia私钥不带0x
SEPOLIA_RPC=https://rpc.sepolia.org
ETHERSCAN_API_KEY=可选
```

2. 确保账户已有 Sepolia ETH（从 https://sepoliafaucet.com/ 领）

3. 部署：

```bash
npm run deploy:sepolia
```

4. 把控制台输出的 `EduToken` 和 `EduSwap` 合约地址填入 `frontend/index.html` 顶部的 `CONFIG.router` 和 `CONFIG.edutoken`。

5. 用 `npx serve frontend` 打开前端，连接 MetaMask 切换到 Sepolia 即可体验。

## 测试

```bash
npx hardhat test test/EduSwap.js
```

## 防御方法（教学总结）

- **精确授权**：每次 `approve(spender, exactAmount)`
- **及时撤销**：`approve(spender, 0)`
- **使用 Permit / Permit2**：链下签名，链上不再有持久授权
- **定期检查授权**：用 [Revoke.cash](https://revoke.cash) 等工具
- **合约代码审计**：警惕要求无限授权的合约
