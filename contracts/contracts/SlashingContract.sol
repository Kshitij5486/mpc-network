// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================
// SlashingContract.sol — Cheat Detection & Punishment
// ============================================
// This is the enforcement layer of the MPC network.
//
// When a node cheats (submits wrong computation,
// tampers with shares, or aborts maliciously),
// any party can submit evidence here.
//
// The contract:
// 1. Records the slash report
// 2. Verifies the evidence is valid
// 3. Calls StakingContract to slash the node
// 4. Calls JobRegistry to fail the job
// 5. Distributes a reward to the reporter
//
// In Phase 4 (ZK proofs), the verify step will
// use a ZK-STARK verifier contract to check
// mathematical proof of cheating. For now we
// implement the governance and slash mechanics.
//
// Types of slashable offences:
// - MAC_FAILURE: submitted share with invalid MAC
// - ABORT: maliciously aborted computation
// - WRONG_RESULT: submitted incorrect output
// - DOUBLE_SIGN: signed two conflicting messages
// ============================================

import "./StakingContract.sol";
import "./MPCToken.sol";

contract SlashingContract {

    // ── Offence types ─────────────────────────
    enum OffenceType {
        MacFailure,    // 0 — invalid MAC tag on share
        Abort,         // 1 — malicious abort
        WrongResult,   // 2 — submitted wrong output
        DoubleSign     // 3 — signed conflicting messages
    }

    // ── Slash report status ───────────────────
    enum ReportStatus {
        Pending,    // 0 — submitted, under review
        Confirmed,  // 1 — slash executed
        Rejected,   // 2 — report was invalid
        Expired     // 3 — too old to process
    }

    // ── Slash report ──────────────────────────
    struct SlashReport {
        uint256 reportId;
        uint256 jobId;
        address reporter;
        address accused;
        OffenceType offence;
        ReportStatus status;
        uint256 slashAmount;
        bytes evidence;
        uint256 createdAt;
        uint256 resolvedAt;
        string description;
    }

    // ── State ─────────────────────────────────
    StakingContract public stakingContract;
    MPCToken public token;
    address public owner;

    uint256 public reportCount;
    mapping(uint256 => SlashReport) public reports;

    mapping(address => uint256[]) public accusedReports;
    mapping(address => uint256[]) public reporterReports;
    mapping(uint256 => uint256[]) public jobReports;

    uint256 public reporterRewardBps;
    uint256 public reportExpiry;

    mapping(OffenceType => uint256) public minSlashAmount;

    mapping(address => mapping(uint256 => bool)) public slashedForJob;

    // ── Events ────────────────────────────────
    event ReportSubmitted(
        uint256 indexed reportId,
        uint256 indexed jobId,
        address indexed accused,
        OffenceType offence
    );

    event SlashExecuted(
        uint256 indexed reportId,
        address indexed accused,
        uint256 amount,
        OffenceType offence
    );

    event ReportRejected(
        uint256 indexed reportId,
        string reason
    );

    event ReporterRewarded(
        address indexed reporter,
        uint256 amount
    );

    // ── Modifiers ─────────────────────────────
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "SlashingContract: not owner"
        );
        _;
    }

    modifier reportExists(uint256 reportId) {
        require(
            reportId > 0 && reportId <= reportCount,
            "SlashingContract: report does not exist"
        );
        _;
    }

    // ── Constructor ───────────────────────────
    constructor(
        address stakingAddress,
        address tokenAddress,
        uint256 _reporterRewardBps,
        uint256 _reportExpiry
    ) {
        owner = msg.sender;
        stakingContract = StakingContract(stakingAddress);
        token = MPCToken(tokenAddress);
        reporterRewardBps = _reporterRewardBps;
        reportExpiry = _reportExpiry;

        minSlashAmount[OffenceType.MacFailure]  = 100 ether;
        minSlashAmount[OffenceType.Abort]       = 50 ether;
        minSlashAmount[OffenceType.WrongResult] = 200 ether;
        minSlashAmount[OffenceType.DoubleSign]  = 150 ether;
    }

    // ============================================
    // submitReport — anyone can report a cheater
    // ============================================
    function submitReport(
        uint256 jobId,
        address accused,
        OffenceType offence,
        bytes calldata evidence,
        string calldata description
    ) external returns (uint256) {
        require(
            accused != address(0),
            "SlashingContract: zero address accused"
        );
        require(
            accused != msg.sender,
            "SlashingContract: cannot report yourself"
        );
        require(
            !slashedForJob[accused][jobId],
            "SlashingContract: already slashed for this job"
        );
        // Fixed: use getStake() instead of nodes().stakedAmount
        require(
            stakingContract.isActiveNode(accused) ||
            stakingContract.getStake(accused) > 0,
            "SlashingContract: accused has no stake"
        );

        reportCount++;

        uint256 slashAmount = minSlashAmount[offence];

        reports[reportCount] = SlashReport({
            reportId: reportCount,
            jobId: jobId,
            reporter: msg.sender,
            accused: accused,
            offence: offence,
            status: ReportStatus.Pending,
            slashAmount: slashAmount,
            evidence: evidence,
            createdAt: block.timestamp,
            resolvedAt: 0,
            description: description
        });

        accusedReports[accused].push(reportCount);
        reporterReports[msg.sender].push(reportCount);
        jobReports[jobId].push(reportCount);

        emit ReportSubmitted(reportCount, jobId, accused, offence);
        return reportCount;
    }

    // ============================================
    // confirmSlash — owner confirms and executes slash
    // ============================================
    function confirmSlash(
        uint256 reportId
    ) external onlyOwner reportExists(reportId) {
        SlashReport storage report = reports[reportId];

        require(
            report.status == ReportStatus.Pending,
            "SlashingContract: report not pending"
        );
        require(
            block.timestamp <= report.createdAt + reportExpiry,
            "SlashingContract: report expired"
        );

        report.status = ReportStatus.Confirmed;
        report.resolvedAt = block.timestamp;

        slashedForJob[report.accused][report.jobId] = true;

        uint256 actualStake = stakingContract.getStake(
            report.accused
        );
        uint256 slashAmount = report.slashAmount > actualStake
            ? actualStake
            : report.slashAmount;

        if (slashAmount > 0) {
            stakingContract.slash(
                report.accused,
                slashAmount,
                _offenceToString(report.offence)
            );

            uint256 reward = (slashAmount * reporterRewardBps) / 10000;
            if (reward > 0) {
                token.transfer(report.reporter, reward);
                emit ReporterRewarded(report.reporter, reward);
            }
        }

        stakingContract.recordJobFailed(report.accused);

        emit SlashExecuted(
            reportId,
            report.accused,
            slashAmount,
            report.offence
        );
    }

    // ============================================
    // rejectReport — owner rejects invalid report
    // ============================================
    function rejectReport(
        uint256 reportId,
        string calldata reason
    ) external onlyOwner reportExists(reportId) {
        SlashReport storage report = reports[reportId];
        require(
            report.status == ReportStatus.Pending,
            "SlashingContract: report not pending"
        );

        report.status = ReportStatus.Rejected;
        report.resolvedAt = block.timestamp;

        emit ReportRejected(reportId, reason);
    }

    // ============================================
    // expireReport — mark old reports as expired
    // ============================================
    function expireReport(uint256 reportId)
        external
        reportExists(reportId)
    {
        SlashReport storage report = reports[reportId];
        require(
            report.status == ReportStatus.Pending,
            "SlashingContract: report not pending"
        );
        require(
            block.timestamp > report.createdAt + reportExpiry,
            "SlashingContract: report not yet expired"
        );

        report.status = ReportStatus.Expired;
        report.resolvedAt = block.timestamp;
    }

    // ============================================
    // recordSuccess — reward honest nodes
    // ============================================
    function recordSuccess(
        address nodeAddress
    ) external onlyOwner {
        stakingContract.recordJobCompleted(nodeAddress);
    }

    // ── View functions ────────────────────────

    function getReport(uint256 reportId)
        external
        view
        reportExists(reportId)
        returns (SlashReport memory)
    {
        return reports[reportId];
    }

    function getAccusedReports(address accused)
        external
        view
        returns (uint256[] memory)
    {
        return accusedReports[accused];
    }

    function getJobReports(uint256 jobId)
        external
        view
        returns (uint256[] memory)
    {
        return jobReports[jobId];
    }

    function getReporterReports(address reporter)
        external
        view
        returns (uint256[] memory)
    {
        return reporterReports[reporter];
    }

    function isSlashedForJob(
        address node,
        uint256 jobId
    ) external view returns (bool) {
        return slashedForJob[node][jobId];
    }

    function setReporterReward(
        uint256 _reporterRewardBps
    ) external onlyOwner {
        require(
            _reporterRewardBps <= 3000,
            "SlashingContract: reward too high"
        );
        reporterRewardBps = _reporterRewardBps;
    }

    function setMinSlashAmount(
        OffenceType offence,
        uint256 amount
    ) external onlyOwner {
        minSlashAmount[offence] = amount;
    }

    function setReportExpiry(
        uint256 _expiry
    ) external onlyOwner {
        reportExpiry = _expiry;
    }

    // ── Internal helpers ──────────────────────

    function _offenceToString(
        OffenceType offence
    ) internal pure returns (string memory) {
        if (offence == OffenceType.MacFailure)
            return "MAC_FAILURE";
        if (offence == OffenceType.Abort)
            return "ABORT";
        if (offence == OffenceType.WrongResult)
            return "WRONG_RESULT";
        if (offence == OffenceType.DoubleSign)
            return "DOUBLE_SIGN";
        return "UNKNOWN";
    }
}