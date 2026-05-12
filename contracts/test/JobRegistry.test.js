const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("JobRegistry", function () {
  let token;
  let registry;
  let owner;
  let client;
  let node1;
  let node2;
  let node3;

  const INITIAL_SUPPLY = ethers.parseEther("1000000");
  const MIN_FEE = ethers.parseEther("10");
  const JOB_FEE = ethers.parseEther("100");

  beforeEach(async function () {
    [owner, client, node1, node2, node3] = await ethers.getSigners();

    // Deploy token
    const MPCToken = await ethers.getContractFactory("MPCToken");
    token = await MPCToken.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();

    // Deploy registry
    const JobRegistry = await ethers.getContractFactory("JobRegistry");
    registry = await JobRegistry.deploy(
      await token.getAddress(),
      MIN_FEE
    );
    await registry.waitForDeployment();

    // Give client some tokens
    await token.transfer(client.address, ethers.parseEther("10000"));

    // Client approves registry to spend tokens
    await token.connect(client).approve(
      await registry.getAddress(),
      ethers.parseEther("10000")
    );
  });

  // ── Deployment ──────────────────────────────

  describe("Deployment", function () {
    it("should set correct owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("should set correct token address", async function () {
      expect(await registry.token()).to.equal(
        await token.getAddress()
      );
    });

    it("should set correct min fee", async function () {
      expect(await registry.minFee()).to.equal(MIN_FEE);
    });

    it("should start with zero jobs", async function () {
      expect(await registry.jobCount()).to.equal(0);
    });
  });

  // ── Post Job ────────────────────────────────

  describe("Post Job", function () {
    it("should post a job successfully", async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      expect(await registry.jobCount()).to.equal(1);
    });

    it("should lock fee in contract", async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      expect(
        await token.balanceOf(await registry.getAddress())
      ).to.equal(JOB_FEE);
    });

    it("should emit JobPosted event", async function () {
      await expect(
        registry.connect(client).postJob(
          JOB_FEE, 2, 3, "hash123", "sum"
        )
      ).to.emit(registry, "JobPosted")
       .withArgs(1, client.address, JOB_FEE, "sum");
    });

    it("should revert if fee too low", async function () {
      await expect(
        registry.connect(client).postJob(
          ethers.parseEther("1"), 2, 3, "hash123", "sum"
        )
      ).to.be.revertedWith("JobRegistry: fee too low");
    });

    it("should revert if less than 2 nodes", async function () {
      await expect(
        registry.connect(client).postJob(
          JOB_FEE, 1, 3, "hash123", "sum"
        )
      ).to.be.revertedWith("JobRegistry: need at least 2 nodes");
    });

    it("should revert with empty input hash", async function () {
      await expect(
        registry.connect(client).postJob(
          JOB_FEE, 2, 3, "", "sum"
        )
      ).to.be.revertedWith("JobRegistry: empty input hash");
    });

    it("should track client jobs", async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      const clientJobIds = await registry.getClientJobs(
        client.address
      );
      expect(clientJobIds.length).to.equal(1);
      expect(clientJobIds[0]).to.equal(1);
    });
  });

  // ── Accept Job ──────────────────────────────

  describe("Accept Job", function () {
    beforeEach(async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
    });

    it("should allow node to accept job", async function () {
      await registry.connect(node1).acceptJob(1);
      const nodes = await registry.getAssignedNodes(1);
      expect(nodes).to.include(node1.address);
    });

    it("should emit JobAccepted event", async function () {
      await expect(registry.connect(node1).acceptJob(1))
        .to.emit(registry, "JobAccepted")
        .withArgs(1, node1.address);
    });

    it("should auto-start when min nodes reached", async function () {
      await registry.connect(node1).acceptJob(1);
      await expect(registry.connect(node2).acceptJob(1))
        .to.emit(registry, "JobStarted");
      const job = await registry.getJob(1);
      expect(job.status).to.equal(1); // Active
    });

    it("should revert if node already assigned", async function () {
      await registry.connect(node1).acceptJob(1);
      await expect(
        registry.connect(node1).acceptJob(1)
      ).to.be.revertedWith("JobRegistry: node already assigned");
    });

    it("should revert if job is full", async function () {
  // Post a new job with maxNodes = 2
  await registry.connect(client).postJob(
    JOB_FEE, 2, 2, "hash456", "sum"
  );
  const jobId = 2;
  // node1 accepts — still pending (need 2 for minNodes)
  // but maxNodes is also 2 so after node2 it auto-starts
  // We need a job where minNodes < maxNodes to test fullness
  // Post job with minNodes=3, maxNodes=3
  await registry.connect(client).postJob(
    JOB_FEE, 3, 3, "hash789", "sum"
  );
  const fullJobId = 3;
  await registry.connect(node1).acceptJob(fullJobId);
  await registry.connect(node2).acceptJob(fullJobId);
  await registry.connect(node3).acceptJob(fullJobId);
  // Job is now active (3 of 3 nodes)
  // Extra node tries to join active job
  const [,,,,, extra] = await ethers.getSigners();
  await expect(
    registry.connect(extra).acceptJob(fullJobId)
  ).to.be.revertedWith("JobRegistry: job not pending");
});

    it("should track node jobs", async function () {
      await registry.connect(node1).acceptJob(1);
      const nodeJobIds = await registry.getNodeJobs(node1.address);
      expect(nodeJobIds.length).to.equal(1);
    });
  });

  // ── Complete Job ────────────────────────────

  describe("Complete Job", function () {
    beforeEach(async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      await registry.connect(node1).acceptJob(1);
      await registry.connect(node2).acceptJob(1);
      // Job is now Active
    });

    it("should complete job with result", async function () {
      await registry.connect(node1).completeJob(1, 42);
      const job = await registry.getJob(1);
      expect(job.status).to.equal(2); // Complete
      expect(job.result).to.equal(42);
    });

    it("should emit JobCompleted event", async function () {
      await expect(registry.connect(node1).completeJob(1, 42))
        .to.emit(registry, "JobCompleted")
        .withArgs(1, 42, node1.address);
    });

    it("should distribute fee to nodes", async function () {
      const before1 = await token.balanceOf(node1.address);
      const before2 = await token.balanceOf(node2.address);
      await registry.connect(node1).completeJob(1, 42);
      const after1 = await token.balanceOf(node1.address);
      const after2 = await token.balanceOf(node2.address);
      // Each node gets half the fee
      expect(after1 - before1).to.equal(JOB_FEE / 2n);
      expect(after2 - before2).to.equal(JOB_FEE / 2n);
    });

    it("should revert complete from non-assigned node", async function () {
      await expect(
        registry.connect(node3).completeJob(1, 42)
      ).to.be.revertedWith("JobRegistry: caller not assigned node");
    });
  });

  // ── Cancel Job ──────────────────────────────

  describe("Cancel Job", function () {
    beforeEach(async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
    });

    it("should allow client to cancel pending job", async function () {
      const before = await token.balanceOf(client.address);
      await registry.connect(client).cancelJob(1);
      const job = await registry.getJob(1);
      expect(job.status).to.equal(4); // Cancelled
      // Fee refunded
      expect(await token.balanceOf(client.address))
        .to.equal(before + JOB_FEE);
    });

    it("should emit JobCancelled event", async function () {
      await expect(registry.connect(client).cancelJob(1))
        .to.emit(registry, "JobCancelled")
        .withArgs(1, client.address);
    });

    it("should revert cancel from non-client", async function () {
      await expect(
        registry.connect(node1).cancelJob(1)
      ).to.be.revertedWith("JobRegistry: not job client");
    });

    it("should revert cancel of active job", async function () {
      await registry.connect(node1).acceptJob(1);
      await registry.connect(node2).acceptJob(1);
      await expect(
        registry.connect(client).cancelJob(1)
      ).to.be.revertedWith(
        "JobRegistry: can only cancel pending jobs"
      );
    });
  });

  // ── View Functions ──────────────────────────

  describe("View Functions", function () {
    it("should return correct job data", async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      const job = await registry.getJob(1);
      expect(job.client).to.equal(client.address);
      expect(job.fee).to.equal(JOB_FEE);
      expect(job.operationType).to.equal("sum");
    });

    it("should check if node is assigned", async function () {
      await registry.connect(client).postJob(
        JOB_FEE, 2, 3, "hash123", "sum"
      );
      await registry.connect(node1).acceptJob(1);
      expect(
        await registry.isNodeAssigned(1, node1.address)
      ).to.equal(true);
      expect(
        await registry.isNodeAssigned(1, node2.address)
      ).to.equal(false);
    });

    it("should revert getJob for nonexistent job", async function () {
      await expect(
        registry.getJob(999)
      ).to.be.revertedWith("JobRegistry: job does not exist");
    });
  });
});