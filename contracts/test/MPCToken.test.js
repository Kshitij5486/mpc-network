const { expect } = require("chai");
const { ethers } = require("hardhat");

// ============================================
// MPCToken Tests
// ============================================
// Tests every function of the token contract.
// Every state transition is covered.
// ============================================

describe("MPCToken", function () {
  let token;
  let owner;
  let node1;
  let node2;
  let node3;

  // Initial supply: 1 million tokens
  const INITIAL_SUPPLY = ethers.parseEther("1000000");

  // Deploy fresh contract before each test
  beforeEach(async function () {
    [owner, node1, node2, node3] = await ethers.getSigners();

    const MPCToken = await ethers.getContractFactory("MPCToken");
    token = await MPCToken.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();
  });

  // ── Deployment ────────────────────────────

  describe("Deployment", function () {
    it("should set correct token name", async function () {
      expect(await token.name()).to.equal("MPC Network Token");
    });

    it("should set correct token symbol", async function () {
      expect(await token.symbol()).to.equal("MPCT");
    });

    it("should set correct decimals", async function () {
      expect(await token.decimals()).to.equal(18);
    });

    it("should mint initial supply to owner", async function () {
      expect(await token.balanceOf(owner.address))
        .to.equal(INITIAL_SUPPLY);
    });

    it("should set total supply correctly", async function () {
      expect(await token.totalSupply()).to.equal(INITIAL_SUPPLY);
    });

    it("should set deployer as owner", async function () {
      expect(await token.owner()).to.equal(owner.address);
    });
  });

  // ── Transfer ──────────────────────────────

  describe("Transfer", function () {
    it("should transfer tokens between accounts", async function () {
      const amount = ethers.parseEther("100");
      await token.transfer(node1.address, amount);
      expect(await token.balanceOf(node1.address)).to.equal(amount);
    });

    it("should reduce sender balance on transfer", async function () {
      const amount = ethers.parseEther("100");
      const before = await token.balanceOf(owner.address);
      await token.transfer(node1.address, amount);
      expect(await token.balanceOf(owner.address))
        .to.equal(before - amount);
    });

    it("should emit Transfer event", async function () {
      const amount = ethers.parseEther("50");
      await expect(token.transfer(node1.address, amount))
        .to.emit(token, "Transfer")
        .withArgs(owner.address, node1.address, amount);
    });

    it("should revert on insufficient balance", async function () {
      const amount = ethers.parseEther("100");
      await expect(
        token.connect(node1).transfer(node2.address, amount)
      ).to.be.revertedWith("MPCToken: insufficient balance");
    });

    it("should revert transfer to zero address", async function () {
      await expect(
        token.transfer(ethers.ZeroAddress, 100)
      ).to.be.revertedWith("MPCToken: transfer to zero address");
    });
  });

  // ── Approve and TransferFrom ───────────────

  describe("Approve and TransferFrom", function () {
    it("should approve spender", async function () {
      const amount = ethers.parseEther("500");
      await token.approve(node1.address, amount);
      expect(await token.allowance(owner.address, node1.address))
        .to.equal(amount);
    });

    it("should emit Approval event", async function () {
      const amount = ethers.parseEther("500");
      await expect(token.approve(node1.address, amount))
        .to.emit(token, "Approval")
        .withArgs(owner.address, node1.address, amount);
    });

    it("should allow transferFrom with approval", async function () {
      const amount = ethers.parseEther("200");
      await token.approve(node1.address, amount);
      await token.connect(node1).transferFrom(
        owner.address,
        node2.address,
        amount
      );
      expect(await token.balanceOf(node2.address)).to.equal(amount);
    });

    it("should reduce allowance after transferFrom", async function () {
      const amount = ethers.parseEther("200");
      await token.approve(node1.address, amount);
      await token.connect(node1).transferFrom(
        owner.address,
        node2.address,
        amount
      );
      expect(
        await token.allowance(owner.address, node1.address)
      ).to.equal(0);
    });

    it("should revert transferFrom without approval", async function () {
      await expect(
        token.connect(node1).transferFrom(
          owner.address,
          node2.address,
          100
        )
      ).to.be.revertedWith("MPCToken: insufficient allowance");
    });
  });

  // ── Mint ──────────────────────────────────

  describe("Mint", function () {
    it("should allow owner to mint tokens", async function () {
      const amount = ethers.parseEther("1000");
      await token.mint(node1.address, amount);
      expect(await token.balanceOf(node1.address)).to.equal(amount);
    });

    it("should increase total supply on mint", async function () {
      const amount = ethers.parseEther("1000");
      const before = await token.totalSupply();
      await token.mint(node1.address, amount);
      expect(await token.totalSupply()).to.equal(before + amount);
    });

    it("should revert mint from non-owner", async function () {
      await expect(
        token.connect(node1).mint(node2.address, 100)
      ).to.be.revertedWith("MPCToken: caller is not owner");
    });

    it("should emit Mint event", async function () {
      const amount = ethers.parseEther("500");
      await expect(token.mint(node1.address, amount))
        .to.emit(token, "Mint")
        .withArgs(node1.address, amount);
    });
  });

  // ── Burn ──────────────────────────────────

  describe("Burn", function () {
    it("should allow owner to burn tokens", async function () {
      const amount = ethers.parseEther("100");
      await token.transfer(node1.address, amount);
      await token.burn(node1.address, amount);
      expect(await token.balanceOf(node1.address)).to.equal(0);
    });

    it("should decrease total supply on burn", async function () {
      const amount = ethers.parseEther("100");
      await token.transfer(node1.address, amount);
      const before = await token.totalSupply();
      await token.burn(node1.address, amount);
      expect(await token.totalSupply()).to.equal(before - amount);
    });

    it("should revert burn from non-owner", async function () {
      await expect(
        token.connect(node1).burn(owner.address, 100)
      ).to.be.revertedWith("MPCToken: caller is not owner");
    });

    it("should revert burn exceeding balance", async function () {
      await expect(
        token.burn(node1.address, ethers.parseEther("100"))
      ).to.be.revertedWith("MPCToken: burn amount exceeds balance");
    });

    it("should emit Burn event", async function () {
      const amount = ethers.parseEther("100");
      await token.transfer(node1.address, amount);
      await expect(token.burn(node1.address, amount))
        .to.emit(token, "Burn")
        .withArgs(node1.address, amount);
    });
  });

  // ── Ownership ─────────────────────────────

  describe("Ownership", function () {
    it("should transfer ownership", async function () {
      await token.transferOwnership(node1.address);
      expect(await token.owner()).to.equal(node1.address);
    });

    it("should revert ownership transfer from non-owner", async function () {
      await expect(
        token.connect(node1).transferOwnership(node2.address)
      ).to.be.revertedWith("MPCToken: caller is not owner");
    });

    it("should revert transfer to zero address", async function () {
      await expect(
        token.transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("MPCToken: new owner is zero address");
    });
  });
});