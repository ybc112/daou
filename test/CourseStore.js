const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CourseStore", function () {
  let token, store;
  let owner, treasury, buyer;

  const INITIAL_SUPPLY = ethers.parseEther("1000000");
  const BUYER_BALANCE = ethers.parseEther("1000");
  const BNB_PRICE = ethers.parseEther("0.01");
  const TOKEN_PRICE = ethers.parseEther("99");

  beforeEach(async function () {
    [owner, treasury, buyer] = await ethers.getSigners();

    const Token = await ethers.getContractFactory("EduToken");
    token = await Token.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();
    await token.transfer(buyer.address, BUYER_BALANCE);

    const CourseStore = await ethers.getContractFactory("CourseStore");
    store = await CourseStore.deploy(owner.address, treasury.address, await token.getAddress());
    await store.waitForDeployment();

    await store.setProduct(1, "校园教学无限授权课程包", BNB_PRICE, TOKEN_PRICE, true);
  });

  it("allows a buyer to pay with native BNB", async function () {
    await expect(
      store.connect(buyer).purchaseWithBNB(1, { value: BNB_PRICE })
    ).to.changeEtherBalances([buyer, treasury], [-BNB_PRICE, BNB_PRICE]);
  });

  it("allows a buyer to pay with an exact BEP20 allowance", async function () {
    await token.connect(buyer).approve(await store.getAddress(), TOKEN_PRICE);

    await expect(store.connect(buyer).purchaseWithToken(1))
      .to.emit(store, "Purchased")
      .withArgs(buyer.address, 1, "校园教学无限授权课程包", await token.getAddress(), TOKEN_PRICE);

    expect(await token.balanceOf(treasury.address)).to.equal(TOKEN_PRICE);
    expect(await token.allowance(buyer.address, await store.getAddress())).to.equal(0);
  });

  it("rejects incorrect BNB payment amounts", async function () {
    await expect(
      store.connect(buyer).purchaseWithBNB(1, { value: ethers.parseEther("0.02") })
    ).to.be.revertedWith("Incorrect BNB amount");
  });
});
