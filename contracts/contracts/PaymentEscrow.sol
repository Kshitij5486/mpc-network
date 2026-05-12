// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================
// PaymentEscrow.sol — Fee Lock and Release
// ============================================
// This contract holds client payments safely
// until a job is completed correctly.
//
// Why escrow matters:
// Without escrow, a client could refuse to pay
// after nodes do the work. With escrow, payment
// is locked upfront and released automatically
// when the job completes with a valid proof.
//
// Flow:
// 1. Client deposits fee into escrow
// 2. Nodes complete the job
// 3. JobRegistry calls release() → nodes paid
// OR
// 3. Job fails → client calls refund()
//
// The escrow contract is the financial backbone
// that makes trustless computation possible.
// ============================================

import "./MPCToken.sol";

contract PaymentEscrow {

    // ── Escrow status ─────────────────────────
    enum EscrowStatus {
        Pending,   // 0 — funds locked, job running
        Released,  // 1 — funds sent to nodes
        Refunded,  // 2 — funds returned to client
        Disputed   // 3 — under dispute resolution
    }

    // ── Escrow record ─────────────────────────
    struct Escrow {
        uint256 escrowId;
        uint256 jobId;
        address client;
        uint256 amount;
        EscrowStatus status;
        address[] beneficiaries; // nodes to pay
        uint256 createdAt;
        uint256 releasedAt;
    }

    // ── State ─────────────────────────────────
    MPCToken public token;
    address public owner;
    address public jobRegistry; // only registry can release

    uint256 public escrowCount;
    mapping(uint256 => Escrow) public escrows;
    mapping(uint256 => uint256) public jobToEscrow; // jobId -> escrowId

    // platform fee percentage (in basis points, 100 = 1%)
    uint256 public platformFeeBps;
    uint256 public platformFeeCollected;

    // ── Events ────────────────────────────────
    event EscrowCreated(
        uint256 indexed escrowId,
        uint256 indexed jobId,
        address indexed client,
        uint256 amount
    );

    event EscrowReleased(
        uint256 indexed escrowId,
        uint256 indexed jobId,
        uint256 amount,
        uint256 platformFee
    );

    event EscrowRefunded(
        uint256 indexed escrowId,
        uint256 indexed jobId,
        address indexed client,
        uint256 amount
    );

    event EscrowDisputed(
        uint256 indexed escrowId,
        string reason
    );

    // ── Modifiers ─────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "PaymentEscrow: not owner");
        _;
    }

    modifier onlyRegistry() {
        require(
            msg.sender == jobRegistry || msg.sender == owner,
            "PaymentEscrow: not authorized"
        );
        _;
    }

    modifier escrowExists(uint256 escrowId) {
        require(
            escrowId > 0 && escrowId <= escrowCount,
            "PaymentEscrow: escrow does not exist"
        );
        _;
    }

    // ── Constructor ───────────────────────────
    constructor(
        address tokenAddress,
        uint256 _platformFeeBps
    ) {
        owner = msg.sender;
        token = MPCToken(tokenAddress);
        platformFeeBps = _platformFeeBps;
    }

    // ============================================
    // createEscrow — lock client payment
    // ============================================
    // Called when a client posts a job.
    // Client must approve this contract first.
    function createEscrow(
        uint256 jobId,
        uint256 amount,
        address[] calldata beneficiaries
    ) external returns (uint256) {
        require(amount > 0, "PaymentEscrow: zero amount");
        require(
            beneficiaries.length > 0,
            "PaymentEscrow: no beneficiaries"
        );
        require(
            jobToEscrow[jobId] == 0,
            "PaymentEscrow: escrow already exists for job"
        );

        // Lock funds from client
        require(
            token.transferFrom(msg.sender, address(this), amount),
            "PaymentEscrow: transfer failed"
        );

        escrowCount++;

        escrows[escrowCount] = Escrow({
            escrowId: escrowCount,
            jobId: jobId,
            client: msg.sender,
            amount: amount,
            status: EscrowStatus.Pending,
            beneficiaries: beneficiaries,
            createdAt: block.timestamp,
            releasedAt: 0
        });

        jobToEscrow[jobId] = escrowCount;

        emit EscrowCreated(escrowCount, jobId, msg.sender, amount);
        return escrowCount;
    }

    // ============================================
    // release — pay nodes after job completes
    // ============================================
    // Only JobRegistry can call this.
    // Platform fee is deducted before paying nodes.
    function release(uint256 jobId) external onlyRegistry {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");

        Escrow storage escrow = escrows[escrowId];
        require(
            escrow.status == EscrowStatus.Pending,
            "PaymentEscrow: escrow not pending"
        );

        escrow.status = EscrowStatus.Released;
        escrow.releasedAt = block.timestamp;

        // Calculate platform fee
        uint256 fee = (escrow.amount * platformFeeBps) / 10000;
        uint256 payableAmount = escrow.amount - fee;
        platformFeeCollected += fee;

        // Distribute equally among beneficiaries
        uint256 count = escrow.beneficiaries.length;
        uint256 sharePerNode = payableAmount / count;

        for (uint i = 0; i < count; i++) {
            token.transfer(escrow.beneficiaries[i], sharePerNode);
        }

        // Transfer platform fee to owner
        if (fee > 0) {
            token.transfer(owner, fee);
        }

        emit EscrowReleased(escrowId, jobId, payableAmount, fee);
    }

    // ============================================
    // refund — return payment to client
    // ============================================
    // Called when job fails or is cancelled.
    function refund(uint256 jobId) external onlyRegistry {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");

        Escrow storage escrow = escrows[escrowId];
        require(
            escrow.status == EscrowStatus.Pending,
            "PaymentEscrow: escrow not pending"
        );

        escrow.status = EscrowStatus.Refunded;

        token.transfer(escrow.client, escrow.amount);

        emit EscrowRefunded(
            escrowId,
            jobId,
            escrow.client,
            escrow.amount
        );
    }

    // ============================================
    // dispute — flag escrow for manual resolution
    // ============================================
    function dispute(
        uint256 jobId,
        string calldata reason
    ) external {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");

        Escrow storage escrow = escrows[escrowId];
        require(
            escrow.client == msg.sender || msg.sender == owner,
            "PaymentEscrow: not authorized to dispute"
        );
        require(
            escrow.status == EscrowStatus.Pending,
            "PaymentEscrow: escrow not pending"
        );

        escrow.status = EscrowStatus.Disputed;

        emit EscrowDisputed(escrowId, reason);
    }

    // ============================================
    // resolveDispute — owner resolves manually
    // ============================================
    function resolveDispute(
        uint256 jobId,
        bool releaseToNodes
    ) external onlyOwner {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");

        Escrow storage escrow = escrows[escrowId];
        require(
            escrow.status == EscrowStatus.Disputed,
            "PaymentEscrow: not disputed"
        );

        if (releaseToNodes) {
            escrow.status = EscrowStatus.Released;
            escrow.releasedAt = block.timestamp;
            uint256 count = escrow.beneficiaries.length;
            uint256 sharePerNode = escrow.amount / count;
            for (uint i = 0; i < count; i++) {
                token.transfer(escrow.beneficiaries[i], sharePerNode);
            }
        } else {
            escrow.status = EscrowStatus.Refunded;
            token.transfer(escrow.client, escrow.amount);
        }
    }

    // ── View functions ────────────────────────

    function getEscrow(uint256 escrowId)
        external
        view
        escrowExists(escrowId)
        returns (Escrow memory)
    {
        return escrows[escrowId];
    }

    function getEscrowByJob(uint256 jobId)
        external
        view
        returns (Escrow memory)
    {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");
        return escrows[escrowId];
    }

    function getEscrowStatus(uint256 jobId)
        external
        view
        returns (EscrowStatus)
    {
        uint256 escrowId = jobToEscrow[jobId];
        require(escrowId > 0, "PaymentEscrow: no escrow for job");
        return escrows[escrowId].status;
    }

    function setJobRegistry(address _jobRegistry)
        external
        onlyOwner
    {
        jobRegistry = _jobRegistry;
    }

    function setPlatformFee(uint256 _platformFeeBps)
        external
        onlyOwner
    {
        require(
            _platformFeeBps <= 1000,
            "PaymentEscrow: fee too high"
        );
        platformFeeBps = _platformFeeBps;
    }

    function withdrawPlatformFees() external onlyOwner {
        uint256 amount = platformFeeCollected;
        platformFeeCollected = 0;
        token.transfer(owner, amount);
    }
}