const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SlashingContract", function () {
  let token;
  let staking;
  let slashing;
  let owner;
  let reporter;
  let accused;
  let innocent;

  const INITIAL_SUPPLY = ethers.parseEther("1000000");
  const MIN_STAKE = ethers.parseEther("100");
  const STAKE_AMOUNT = ethers.parseEther("500");
  const LOCKUP = 60;
  const REPORTER_REWARD_BPS = 1000; // 10%
  const REPORT_EXPIRY = 86400; // 24 hours

  beforeEach(async function () {
    [owner, reporter, accused, innocent] =
      await ethers.getSigners();

    // Deploy token
    const MPCToken = await ethers.getContractFactory("MPCToken");
    token = await MPCToken.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();

    // Deploy staking
    const StakingContract = await ethers.getContractFactory(
      "StakingContract"
    );
    staking = await StakingContract.deploy(
      await token.getAddress(),
      MIN_STAKE,
      LOCKUP
    );
    await staking.waitForDeployment();

    // Deploy slashing
    const SlashingContract = await ethers.getContractFactory(
      "SlashingContract"
    );
    slashing = await SlashingContract.deploy(
      await staking.getAddress(),
      await token.getAddress(),
      REPORTER_REWARD_BPS,
      REPORT_EXPIRY
    );
    await slashing.waitForDeployment();

    // Wire up: set slashing contract in staking
    await staking.setSlashingContract(
      await slashing.getAddress()
    );

    // Give accused tokens and stake
    await token.transfer(
      accused.address,
      ethers.parseEther("10000")
    );
    await token.connect(accused).approve(
      await staking.getAddress(),
      ethers.parseEther("10000")
    );
    await staking.connect(accused).stake(STAKE_AMOUNT);

    // Give slashing contract tokens for rewards
    await token.transfer(
      await slashing.getAddress(),
      ethers.parseEther("1000")
    );
  });

  // ── Deployment ──────────────────────────────

  describe("Deployment", function () {
    it("should set correct owner", async function () {
      expect(await slashing.owner()).to.equal(owner.address);
    });

    it("should set correct staking contract", async function () {
      expect(await slashing.stakingContract()).to.equal(
        await staking.getAddress()
      );
    });

    it("should set correct reporter reward", async function () {
      expect(await slashing.reporterRewardBps()).to.equal(
        REPORTER_REWARD_BPS
      );
    });

    it("should start with zero reports", async function () {
      expect(await slashing.reportCount()).to.equal(0);
    });
  });

  // ── Submit Report ───────────────────────────

  describe("Submit Report", function () {
    it("should submit a report successfully", async function () {
      await slashing.connect(reporter).submitReport(
        1,
        accused.address,
        0, // MacFailure
        "0x1234",
        "Node submitted invalid MAC"
      );
      expect(await slashing.reportCount()).to.equal(1);
    });

    it("should emit ReportSubmitted event", async function () {
      await expect(
        slashing.connect(reporter).submitReport(
          1, accused.address, 0, "0x", "test"
        )
      ).to.emit(slashing, "ReportSubmitted")
       .withArgs(1, 1, accused.address, 0);
    });

    it("should track reports by accused", async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x", "test"
      );
      const reports = await slashing.getAccusedReports(
        accused.address
      );
      expect(reports.length).to.equal(1);
    });

    it("should track reports by job", async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x", "test"
      );
      const reports = await slashing.getJobReports(1);
      expect(reports.length).to.equal(1);
    });

    it("should revert report against zero address", async function () {
      await expect(
        slashing.connect(reporter).submitReport(
          1, ethers.ZeroAddress, 0, "0x", "test"
        )
      ).to.be.revertedWith(
        "SlashingContract: zero address accused"
      );
    });

    it("should revert self-report", async function () {
      await expect(
        slashing.connect(accused).submitReport(
          1, accused.address, 0, "0x", "test"
        )
      ).to.be.revertedWith(
        "SlashingContract: cannot report yourself"
      );
    });

    it("should revert report against unstaked node", async function () {
      await expect(
        slashing.connect(reporter).submitReport(
          1, innocent.address, 0, "0x", "test"
        )
      ).to.be.revertedWith(
        "SlashingContract: accused has no stake"
      );
    });

    it("should revert duplicate report for same job", async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x", "test"
      );
      await slashing.confirmSlash(1);
      await expect(
        slashing.connect(reporter).submitReport(
          1, accused.address, 0, "0x", "second report"
        )
      ).to.be.revertedWith(
        "SlashingContract: already slashed for this job"
      );
    });
  });

  // ── Confirm Slash ───────────────────────────

  describe("Confirm Slash", function () {
    beforeEach(async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x1234", "MAC failure"
      );
    });

    it("should confirm slash and execute", async function () {
      await slashing.confirmSlash(1);
      const report = await slashing.getReport(1);
      expect(report.status).to.equal(1); // Confirmed
    });

    it("should slash the accused node", async function () {
      const stakeBefore = await staking.getStake(accused.address);
      await slashing.confirmSlash(1);
      const stakeAfter = await staking.getStake(accused.address);
      expect(stakeAfter).to.be.lessThan(stakeBefore);
    });

    it("should reward the reporter", async function () {
      const before = await token.balanceOf(reporter.address);
      await slashing.confirmSlash(1);
      const after = await token.balanceOf(reporter.address);
      expect(after).to.be.greaterThan(before);
    });

    it("should emit SlashExecuted event", async function () {
      await expect(slashing.confirmSlash(1))
        .to.emit(slashing, "SlashExecuted");
    });

    it("should emit ReporterRewarded event", async function () {
      await expect(slashing.confirmSlash(1))
        .to.emit(slashing, "ReporterRewarded");
    });

    it("should mark node as slashed for job", async function () {
      await slashing.confirmSlash(1);
      expect(
        await slashing.isSlashedForJob(accused.address, 1)
      ).to.be.true;
    });

    it("should revert confirm from non-owner", async function () {
      await expect(
        slashing.connect(reporter).confirmSlash(1)
      ).to.be.revertedWith("SlashingContract: not owner");
    });

    it("should revert double confirm", async function () {
      await slashing.confirmSlash(1);
      await expect(
        slashing.confirmSlash(1)
      ).to.be.revertedWith("SlashingContract: report not pending");
    });
  });

  // ── Reject Report ───────────────────────────

  describe("Reject Report", function () {
    beforeEach(async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x", "test"
      );
    });

    it("should reject a report", async function () {
      await slashing.rejectReport(1, "insufficient evidence");
      const report = await slashing.getReport(1);
      expect(report.status).to.equal(2); // Rejected
    });

    it("should emit ReportRejected event", async function () {
      await expect(
        slashing.rejectReport(1, "invalid evidence")
      ).to.emit(slashing, "ReportRejected")
       .withArgs(1, "invalid evidence");
    });

    it("should revert reject from non-owner", async function () {
      await expect(
        slashing.connect(reporter).rejectReport(1, "reason")
      ).to.be.revertedWith("SlashingContract: not owner");
    });

    it("should revert reject of confirmed report", async function () {
      await slashing.confirmSlash(1);
      await expect(
        slashing.rejectReport(1, "too late")
      ).to.be.revertedWith("SlashingContract: report not pending");
    });
  });

  // ── Expire Report ───────────────────────────

  describe("Expire Report", function () {
    beforeEach(async function () {
      await slashing.connect(reporter).submitReport(
        1, accused.address, 0, "0x", "test"
      );
    });

    it("should expire old report", async function () {
      await ethers.provider.send("evm_increaseTime", [
        REPORT_EXPIRY + 1,
      ]);
      await ethers.provider.send("evm_mine");
      await slashing.expireReport(1);
      const report = await slashing.getReport(1);
      expect(report.status).to.equal(3); // Expired
    });

    it("should revert expire on fresh report", async function () {
      await expect(
        slashing.expireReport(1)
      ).to.be.revertedWith(
        "SlashingContract: report not yet expired"
      );
    });
  });

  // ── Admin ───────────────────────────────────

  describe("Admin", function () {
    it("should allow owner to set reporter reward", async function () {
      await slashing.setReporterReward(500);
      expect(await slashing.reporterRewardBps()).to.equal(500);
    });

    it("should revert reward above 30%", async function () {
      await expect(
        slashing.setReporterReward(3001)
      ).to.be.revertedWith("SlashingContract: reward too high");
    });

    it("should allow owner to set min slash amount", async function () {
      await slashing.setMinSlashAmount(0, ethers.parseEther("50"));
      expect(await slashing.minSlashAmount(0))
        .to.equal(ethers.parseEther("50"));
    });

    it("should allow owner to set report expiry", async function () {
      await slashing.setReportExpiry(3600);
      expect(await slashing.reportExpiry()).to.equal(3600);
    });

    it("should allow owner to record success", async function () {
      const before = await staking.getReputation(accused.address);
      await slashing.recordSuccess(accused.address);
      const after = await staking.getReputation(accused.address);
      expect(after).to.be.greaterThan(before);
    });
  });
});