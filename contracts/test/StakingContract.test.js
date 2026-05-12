const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("StakingContract", function () {
  let token;
  let staking;
  let owner;
  let node1;
  let node2;
  let node3;

  const INITIAL_SUPPLY = ethers.parseEther("1000000");
  const MIN_STAKE = ethers.parseEther("100");
  const STAKE_AMOUNT = ethers.parseEther("500");
  const LOCKUP_PERIOD = 60;

  beforeEach(async function () {
    [owner, node1, node2, node3] = await ethers.getSigners();

    const MPCToken = await ethers.getContractFactory("MPCToken");
    token = await MPCToken.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();

    const StakingContract = await ethers.getContractFactory(
      "StakingContract"
    );
    staking = await StakingContract.deploy(
      await token.getAddress(),
      MIN_STAKE,
      LOCKUP_PERIOD
    );
    await staking.waitForDeployment();

    await token.transfer(node1.address, ethers.parseEther("10000"));
    await token.transfer(node2.address, ethers.parseEther("10000"));
    await token.transfer(node3.address, ethers.parseEther("10000"));

    await token.connect(node1).approve(
      await staking.getAddress(),
      ethers.parseEther("10000")
    );
    await token.connect(node2).approve(
      await staking.getAddress(),
      ethers.parseEther("10000")
    );
    await token.connect(node3).approve(
      await staking.getAddress(),
      ethers.parseEther("10000")
    );
  });

  // ── Deployment ──────────────────────────────

  describe("Deployment", function () {
    it("should set correct owner", async function () {
      expect(await staking.owner()).to.equal(owner.address);
    });

    it("should set correct min stake", async function () {
      expect(await staking.minStake()).to.equal(MIN_STAKE);
    });

    it("should set correct lockup period", async function () {
      expect(await staking.unstakeLockup()).to.equal(LOCKUP_PERIOD);
    });

    it("should start with zero total staked", async function () {
      expect(await staking.totalStaked()).to.equal(0);
    });
  });

  // ── Staking ─────────────────────────────────

  describe("Staking", function () {
    it("should allow node to stake", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      expect(await staking.getStake(node1.address))
        .to.equal(STAKE_AMOUNT);
    });

    it("should mark node as active after staking", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      expect(await staking.isActiveNode(node1.address)).to.be.true;
    });

    it("should increase total staked", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      expect(await staking.totalStaked()).to.equal(STAKE_AMOUNT);
    });

    it("should emit NodeStaked event", async function () {
      await expect(staking.connect(node1).stake(STAKE_AMOUNT))
        .to.emit(staking, "NodeStaked")
        .withArgs(node1.address, STAKE_AMOUNT);
    });

    it("should revert if below minimum stake", async function () {
      await expect(
        staking.connect(node1).stake(ethers.parseEther("10"))
      ).to.be.revertedWith("StakingContract: below minimum stake");
    });

    it("should revert if already staked", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      await expect(
        staking.connect(node1).stake(STAKE_AMOUNT)
      ).to.be.revertedWith("StakingContract: already staked");
    });

    it("should set initial reputation to 50", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      expect(await staking.getReputation(node1.address)).to.equal(50);
    });

    it("should increase active node count", async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
      await staking.connect(node2).stake(STAKE_AMOUNT);
      expect(await staking.getActiveNodeCount()).to.equal(2);
    });
  });

  // ── Unstaking ───────────────────────────────

  describe("Unstaking", function () {
    beforeEach(async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
    });

    it("should allow node to request unstake", async function () {
      await staking.connect(node1).requestUnstake();
      const nodeInfo = await staking.nodes(node1.address);
      expect(nodeInfo.status).to.equal(3); // Unstaking = 3
    });

    it("should emit NodeUnstakeRequested event", async function () {
      await expect(staking.connect(node1).requestUnstake())
        .to.emit(staking, "NodeUnstakeRequested");
    });

    it("should revert unstake before lockup ends", async function () {
      await staking.connect(node1).requestUnstake();
      await expect(
        staking.connect(node1).unstake()
      ).to.be.revertedWith("StakingContract: lockup period not over");
    });

    it("should allow unstake after lockup period", async function () {
      await staking.connect(node1).requestUnstake();
      await ethers.provider.send("evm_increaseTime", [LOCKUP_PERIOD + 1]);
      await ethers.provider.send("evm_mine");
      const before = await token.balanceOf(node1.address);
      await staking.connect(node1).unstake();
      const after = await token.balanceOf(node1.address);
      expect(after - before).to.equal(STAKE_AMOUNT);
    });

    it("should decrease active node count after unstake", async function () {
      await staking.connect(node1).requestUnstake();
      await ethers.provider.send("evm_increaseTime", [LOCKUP_PERIOD + 1]);
      await ethers.provider.send("evm_mine");
      await staking.connect(node1).unstake();
      expect(await staking.getActiveNodeCount()).to.equal(0);
    });

    it("should revert request unstake if not active", async function () {
      await staking.connect(node1).requestUnstake();
      await expect(
        staking.connect(node1).requestUnstake()
      ).to.be.revertedWith("StakingContract: node not active");
    });
  });

  // ── Slashing ────────────────────────────────

  describe("Slashing", function () {
    beforeEach(async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
    });

    it("should allow owner to slash a node", async function () {
      const slashAmount = ethers.parseEther("100");
      await staking.slash(
        node1.address,
        slashAmount,
        "MAC verification failed"
      );
      const nodeInfo = await staking.nodes(node1.address);
      expect(nodeInfo.status).to.equal(2); // Slashed = 2
    });

    it("should emit NodeSlashed event", async function () {
      const slashAmount = ethers.parseEther("100");
      await expect(
        staking.slash(node1.address, slashAmount, "cheating")
      ).to.emit(staking, "NodeSlashed")
       .withArgs(node1.address, slashAmount, "cheating");
    });

    it("should set reputation to 0 after slash", async function () {
      await staking.slash(
        node1.address,
        ethers.parseEther("100"),
        "cheating"
      );
      expect(await staking.getReputation(node1.address)).to.equal(0);
    });

    it("should remove node from active list after slash", async function () {
      await staking.slash(
        node1.address,
        ethers.parseEther("100"),
        "cheating"
      );
      expect(await staking.isActiveNode(node1.address)).to.be.false;
      expect(await staking.getActiveNodeCount()).to.equal(0);
    });

    it("should revert slash from non-authorized address", async function () {
      await expect(
        staking.connect(node2).slash(
          node1.address,
          ethers.parseEther("100"),
          "cheating"
        )
      ).to.be.revertedWith(
        "StakingContract: not authorized to slash"
      );
    });
  });

  // ── Reputation ──────────────────────────────

  describe("Reputation", function () {
    beforeEach(async function () {
      await staking.connect(node1).stake(STAKE_AMOUNT);
    });

    it("should increase reputation on job completed", async function () {
      const before = await staking.getReputation(node1.address);
      await staking.recordJobCompleted(node1.address);
      const after = await staking.getReputation(node1.address);
      expect(after).to.be.greaterThan(before);
    });

    it("should decrease reputation on job failed", async function () {
      const before = await staking.getReputation(node1.address);
      await staking.recordJobFailed(node1.address);
      const after = await staking.getReputation(node1.address);
      expect(after).to.be.lessThan(before);
    });

    it("should cap reputation at 100", async function () {
      for (let i = 0; i < 15; i++) {
        await staking.recordJobCompleted(node1.address);
      }
      expect(await staking.getReputation(node1.address)).to.equal(100);
    });

    it("should not go below 0 reputation", async function () {
      for (let i = 0; i < 10; i++) {
        await staking.recordJobFailed(node1.address);
      }
      expect(await staking.getReputation(node1.address)).to.equal(0);
    });

    it("should emit ReputationUpdated event", async function () {
      await expect(staking.recordJobCompleted(node1.address))
        .to.emit(staking, "ReputationUpdated");
    });
  });

  // ── Admin ───────────────────────────────────

  describe("Admin", function () {
    it("should allow owner to set slashing contract", async function () {
      await staking.setSlashingContract(node3.address);
      expect(await staking.slashingContract()).to.equal(node3.address);
    });

    it("should allow owner to update min stake", async function () {
      const newMin = ethers.parseEther("200");
      await staking.setMinStake(newMin);
      expect(await staking.minStake()).to.equal(newMin);
    });

    it("should revert setMinStake from non-owner", async function () {
      await expect(
        staking.connect(node1).setMinStake(100)
      ).to.be.revertedWith("StakingContract: not owner");
    });
  });
});