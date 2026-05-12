const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PaymentEscrow", function () {
  let token;
  let escrow;
  let owner;
  let client;
  let node1;
  let node2;
  let registry;

  const INITIAL_SUPPLY = ethers.parseEther("1000000");
  const ESCROW_AMOUNT = ethers.parseEther("100");
  const PLATFORM_FEE_BPS = 200; // 2%

  beforeEach(async function () {
    [owner, client, node1, node2, registry] =
      await ethers.getSigners();

    const MPCToken = await ethers.getContractFactory("MPCToken");
    token = await MPCToken.deploy(INITIAL_SUPPLY);
    await token.waitForDeployment();

    const PaymentEscrow = await ethers.getContractFactory(
      "PaymentEscrow"
    );
    escrow = await PaymentEscrow.deploy(
      await token.getAddress(),
      PLATFORM_FEE_BPS
    );
    await escrow.waitForDeployment();

    // Set registry
    await escrow.setJobRegistry(registry.address);

    // Give client tokens
    await token.transfer(client.address, ethers.parseEther("10000"));

    // Client approves escrow
    await token.connect(client).approve(
      await escrow.getAddress(),
      ethers.parseEther("10000")
    );
  });

  // ── Deployment ──────────────────────────────

  describe("Deployment", function () {
    it("should set correct owner", async function () {
      expect(await escrow.owner()).to.equal(owner.address);
    });

    it("should set correct platform fee", async function () {
      expect(await escrow.platformFeeBps())
        .to.equal(PLATFORM_FEE_BPS);
    });

    it("should start with zero escrows", async function () {
      expect(await escrow.escrowCount()).to.equal(0);
    });
  });

  // ── Create Escrow ───────────────────────────

  describe("Create Escrow", function () {
    it("should create escrow successfully", async function () {
      await escrow.connect(client).createEscrow(
        1,
        ESCROW_AMOUNT,
        [node1.address, node2.address]
      );
      expect(await escrow.escrowCount()).to.equal(1);
    });

    it("should lock funds in contract", async function () {
      await escrow.connect(client).createEscrow(
        1,
        ESCROW_AMOUNT,
        [node1.address, node2.address]
      );
      expect(
        await token.balanceOf(await escrow.getAddress())
      ).to.equal(ESCROW_AMOUNT);
    });

    it("should emit EscrowCreated event", async function () {
      await expect(
        escrow.connect(client).createEscrow(
          1,
          ESCROW_AMOUNT,
          [node1.address, node2.address]
        )
      ).to.emit(escrow, "EscrowCreated")
       .withArgs(1, 1, client.address, ESCROW_AMOUNT);
    });

    it("should revert with zero amount", async function () {
      await expect(
        escrow.connect(client).createEscrow(
          1, 0, [node1.address]
        )
      ).to.be.revertedWith("PaymentEscrow: zero amount");
    });

    it("should revert with no beneficiaries", async function () {
      await expect(
        escrow.connect(client).createEscrow(
          1, ESCROW_AMOUNT, []
        )
      ).to.be.revertedWith("PaymentEscrow: no beneficiaries");
    });

    it("should revert duplicate escrow for same job", async function () {
      await escrow.connect(client).createEscrow(
        1, ESCROW_AMOUNT, [node1.address]
      );
      await expect(
        escrow.connect(client).createEscrow(
          1, ESCROW_AMOUNT, [node1.address]
        )
      ).to.be.revertedWith(
        "PaymentEscrow: escrow already exists for job"
      );
    });
  });

  // ── Release ─────────────────────────────────

  describe("Release", function () {
    beforeEach(async function () {
      await escrow.connect(client).createEscrow(
        1,
        ESCROW_AMOUNT,
        [node1.address, node2.address]
      );
    });

    it("should release funds to nodes", async function () {
      const before1 = await token.balanceOf(node1.address);
      const before2 = await token.balanceOf(node2.address);
      await escrow.connect(registry).release(1);
      const after1 = await token.balanceOf(node1.address);
      const after2 = await token.balanceOf(node2.address);
      // Each gets half minus platform fee
      expect(after1).to.be.greaterThan(before1);
      expect(after2).to.be.greaterThan(before2);
    });

    it("should deduct platform fee", async function () {
      const ownerBefore = await token.balanceOf(owner.address);
      await escrow.connect(registry).release(1);
      const ownerAfter = await token.balanceOf(owner.address);
      const expectedFee =
        (ESCROW_AMOUNT * BigInt(PLATFORM_FEE_BPS)) / 10000n;
      expect(ownerAfter - ownerBefore).to.equal(expectedFee);
    });

    it("should emit EscrowReleased event", async function () {
      await expect(escrow.connect(registry).release(1))
        .to.emit(escrow, "EscrowReleased");
    });

    it("should mark escrow as released", async function () {
      await escrow.connect(registry).release(1);
      const status = await escrow.getEscrowStatus(1);
      expect(status).to.equal(1); // Released
    });

    it("should revert double release", async function () {
      await escrow.connect(registry).release(1);
      await expect(
        escrow.connect(registry).release(1)
      ).to.be.revertedWith("PaymentEscrow: escrow not pending");
    });

    it("should revert release from non-registry", async function () {
      await expect(
        escrow.connect(client).release(1)
      ).to.be.revertedWith("PaymentEscrow: not authorized");
    });
  });

  // ── Refund ──────────────────────────────────

  describe("Refund", function () {
    beforeEach(async function () {
      await escrow.connect(client).createEscrow(
        1,
        ESCROW_AMOUNT,
        [node1.address, node2.address]
      );
    });

    it("should refund client on job failure", async function () {
      const before = await token.balanceOf(client.address);
      await escrow.connect(registry).refund(1);
      const after = await token.balanceOf(client.address);
      expect(after - before).to.equal(ESCROW_AMOUNT);
    });

    it("should emit EscrowRefunded event", async function () {
      await expect(escrow.connect(registry).refund(1))
        .to.emit(escrow, "EscrowRefunded")
        .withArgs(1, 1, client.address, ESCROW_AMOUNT);
    });

    it("should mark escrow as refunded", async function () {
      await escrow.connect(registry).refund(1);
      const status = await escrow.getEscrowStatus(1);
      expect(status).to.equal(2); // Refunded
    });

    it("should revert double refund", async function () {
      await escrow.connect(registry).refund(1);
      await expect(
        escrow.connect(registry).refund(1)
      ).to.be.revertedWith("PaymentEscrow: escrow not pending");
    });
  });

  // ── Dispute ─────────────────────────────────

  describe("Dispute", function () {
    beforeEach(async function () {
      await escrow.connect(client).createEscrow(
        1,
        ESCROW_AMOUNT,
        [node1.address, node2.address]
      );
    });

    it("should allow client to dispute", async function () {
      await escrow.connect(client).dispute(1, "nodes cheated");
      const status = await escrow.getEscrowStatus(1);
      expect(status).to.equal(3); // Disputed
    });

    it("should emit EscrowDisputed event", async function () {
      await expect(
        escrow.connect(client).dispute(1, "nodes cheated")
      ).to.emit(escrow, "EscrowDisputed");
    });

    it("should allow owner to resolve dispute for nodes", async function () {
      await escrow.connect(client).dispute(1, "test");
      const before = await token.balanceOf(node1.address);
      await escrow.resolveDispute(1, true);
      const after = await token.balanceOf(node1.address);
      expect(after).to.be.greaterThan(before);
    });

    it("should allow owner to resolve dispute for client", async function () {
      await escrow.connect(client).dispute(1, "test");
      const before = await token.balanceOf(client.address);
      await escrow.resolveDispute(1, false);
      const after = await token.balanceOf(client.address);
      expect(after - before).to.equal(ESCROW_AMOUNT);
    });

    it("should revert dispute from non-client", async function () {
      await expect(
        escrow.connect(node1).dispute(1, "test")
      ).to.be.revertedWith(
        "PaymentEscrow: not authorized to dispute"
      );
    });
  });

  // ── Admin ───────────────────────────────────

  describe("Admin", function () {
    it("should allow owner to set platform fee", async function () {
      await escrow.setPlatformFee(300);
      expect(await escrow.platformFeeBps()).to.equal(300);
    });

    it("should revert fee above 10%", async function () {
      await expect(
        escrow.setPlatformFee(1001)
      ).to.be.revertedWith("PaymentEscrow: fee too high");
    });

    it("should allow owner to set job registry", async function () {
      await escrow.setJobRegistry(node1.address);
      expect(await escrow.jobRegistry()).to.equal(node1.address);
    });

    it("should revert setPlatformFee from non-owner", async function () {
      await expect(
        escrow.connect(client).setPlatformFee(100)
      ).to.be.revertedWith("PaymentEscrow: not owner");
    });
  });
});