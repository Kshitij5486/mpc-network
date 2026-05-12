// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================
// JobRegistry.sol — MPC Job Board
// ============================================
// This contract is the coordination heart
// of the MPC network.
//
// How it works:
// 1. Client posts a job with a fee
// 2. Nodes see the job and accept it
// 3. Nodes compute the MPC protocol
// 4. Coordinator marks job complete
// 5. Fee is released to nodes
//
// Every job has a unique ID and tracks:
// - who posted it (client)
// - how much they paid (fee)
// - which nodes are working on it
// - current status (pending/active/complete)
// - the final result
// ============================================

import "./MPCToken.sol";

contract JobRegistry {

    // ── Job status lifecycle ───────────────────
    enum JobStatus {
        Pending,    // posted, waiting for nodes
        Active,     // nodes accepted, computing
        Complete,   // computation finished
        Failed,     // computation failed
        Cancelled   // cancelled by client
    }

    // ── Job struct ────────────────────────────
    struct Job {
        uint256 jobId;
        address client;          // who posted the job
        uint256 fee;             // tokens locked for payment
        uint256 minNodes;        // minimum nodes required
        uint256 maxNodes;        // maximum nodes allowed
        JobStatus status;
        address[] assignedNodes; // nodes working on this job
        uint256 result;          // final computation result
        uint256 createdAt;       // block timestamp
        uint256 completedAt;     // when job finished
        string inputHash;        // hash of encrypted input data
        string operationType;    // "sum", "average", "product"
    }

    // ── State ─────────────────────────────────
    MPCToken public token;
    address public owner;

    uint256 public jobCount;
    mapping(uint256 => Job) public jobs;

    // node address -> list of job IDs they worked on
    mapping(address => uint256[]) public nodeJobs;

    // client address -> list of job IDs they posted
    mapping(address => uint256[]) public clientJobs;

    // minimum fee required to post a job
    uint256 public minFee;

    // ── Events ────────────────────────────────
    event JobPosted(
        uint256 indexed jobId,
        address indexed client,
        uint256 fee,
        string operationType
    );

    event JobAccepted(
        uint256 indexed jobId,
        address indexed node
    );

    event JobStarted(
        uint256 indexed jobId,
        address[] nodes
    );

    event JobCompleted(
        uint256 indexed jobId,
        uint256 result,
        address indexed completedBy
    );

    event JobFailed(
        uint256 indexed jobId,
        string reason
    );

    event JobCancelled(
        uint256 indexed jobId,
        address indexed client
    );

    // ── Modifiers ─────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "JobRegistry: not owner");
        _;
    }

    modifier jobExists(uint256 jobId) {
        require(jobId > 0 && jobId <= jobCount, "JobRegistry: job does not exist");
        _;
    }

    modifier onlyClient(uint256 jobId) {
        require(
            jobs[jobId].client == msg.sender,
            "JobRegistry: not job client"
        );
        _;
    }

    // ── Constructor ───────────────────────────
    constructor(address tokenAddress, uint256 _minFee) {
        owner = msg.sender;
        token = MPCToken(tokenAddress);
        minFee = _minFee;
    }

    // ============================================
    // postJob — client posts a computation job
    // ============================================
    // Client must approve this contract to spend
    // their tokens before calling postJob.
    // Fee is locked in contract until job completes.
    function postJob(
        uint256 fee,
        uint256 minNodes,
        uint256 maxNodes,
        string calldata inputHash,
        string calldata operationType
    ) external returns (uint256) {
        require(fee >= minFee, "JobRegistry: fee too low");
        require(minNodes >= 2, "JobRegistry: need at least 2 nodes");
        require(maxNodes >= minNodes, "JobRegistry: maxNodes < minNodes");
        require(bytes(inputHash).length > 0, "JobRegistry: empty input hash");

        // Transfer fee from client to this contract
        require(
            token.transferFrom(msg.sender, address(this), fee),
            "JobRegistry: fee transfer failed"
        );

        jobCount++;

        jobs[jobCount] = Job({
            jobId: jobCount,
            client: msg.sender,
            fee: fee,
            minNodes: minNodes,
            maxNodes: maxNodes,
            status: JobStatus.Pending,
            assignedNodes: new address[](0),
            result: 0,
            createdAt: block.timestamp,
            completedAt: 0,
            inputHash: inputHash,
            operationType: operationType
        });

        clientJobs[msg.sender].push(jobCount);

        emit JobPosted(jobCount, msg.sender, fee, operationType);
        return jobCount;
    }

    // ============================================
    // acceptJob — node signals it will work on job
    // ============================================
    function acceptJob(uint256 jobId)
        external
        jobExists(jobId)
    {
        Job storage job = jobs[jobId];
        require(
            job.status == JobStatus.Pending,
            "JobRegistry: job not pending"
        );
        require(
            job.assignedNodes.length < job.maxNodes,
            "JobRegistry: job is full"
        );

        // Check node not already assigned
        for (uint i = 0; i < job.assignedNodes.length; i++) {
            require(
                job.assignedNodes[i] != msg.sender,
                "JobRegistry: node already assigned"
            );
        }

        job.assignedNodes.push(msg.sender);
        nodeJobs[msg.sender].push(jobId);

        emit JobAccepted(jobId, msg.sender);

        // Auto-start if minimum nodes reached
        if (job.assignedNodes.length >= job.minNodes) {
            job.status = JobStatus.Active;
            emit JobStarted(jobId, job.assignedNodes);
        }
    }

    // ============================================
    // completeJob — mark job as complete with result
    // ============================================
    // Only assigned nodes can complete a job.
    // Fee is distributed equally among assigned nodes.
    function completeJob(
        uint256 jobId,
        uint256 result
    ) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(
            job.status == JobStatus.Active,
            "JobRegistry: job not active"
        );

        // Verify caller is an assigned node
        bool isAssigned = false;
        for (uint i = 0; i < job.assignedNodes.length; i++) {
            if (job.assignedNodes[i] == msg.sender) {
                isAssigned = true;
                break;
            }
        }
        require(isAssigned, "JobRegistry: caller not assigned node");

        job.status = JobStatus.Complete;
        job.result = result;
        job.completedAt = block.timestamp;

        // Distribute fee equally among nodes
        uint256 nodeCount = job.assignedNodes.length;
        uint256 sharePerNode = job.fee / nodeCount;

        for (uint i = 0; i < nodeCount; i++) {
            token.transfer(job.assignedNodes[i], sharePerNode);
        }

        emit JobCompleted(jobId, result, msg.sender);
    }

    // ============================================
    // failJob — mark job as failed
    // ============================================
    // Called when MPC protocol fails.
    // Fee is refunded to client.
    function failJob(
        uint256 jobId,
        string calldata reason
    ) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(
            job.status == JobStatus.Active ||
            job.status == JobStatus.Pending,
            "JobRegistry: job not active or pending"
        );

        // Verify caller is assigned node or owner
        bool isAssigned = false;
        for (uint i = 0; i < job.assignedNodes.length; i++) {
            if (job.assignedNodes[i] == msg.sender) {
                isAssigned = true;
                break;
            }
        }
        require(
            isAssigned || msg.sender == owner,
            "JobRegistry: not authorized"
        );

        job.status = JobStatus.Failed;

        // Refund fee to client
        token.transfer(job.client, job.fee);

        emit JobFailed(jobId, reason);
    }

    // ============================================
    // cancelJob — client cancels pending job
    // ============================================
    function cancelJob(uint256 jobId)
        external
        jobExists(jobId)
        onlyClient(jobId)
    {
        Job storage job = jobs[jobId];
        require(
            job.status == JobStatus.Pending,
            "JobRegistry: can only cancel pending jobs"
        );

        job.status = JobStatus.Cancelled;

        // Refund fee to client
        token.transfer(job.client, job.fee);

        emit JobCancelled(jobId, msg.sender);
    }

    // ── View functions ────────────────────────

    function getJob(uint256 jobId)
        external
        view
        jobExists(jobId)
        returns (Job memory)
    {
        return jobs[jobId];
    }

    function getAssignedNodes(uint256 jobId)
        external
        view
        jobExists(jobId)
        returns (address[] memory)
    {
        return jobs[jobId].assignedNodes;
    }

    function getClientJobs(address client)
        external
        view
        returns (uint256[] memory)
    {
        return clientJobs[client];
    }

    function getNodeJobs(address node)
        external
        view
        returns (uint256[] memory)
    {
        return nodeJobs[node];
    }

    function isNodeAssigned(uint256 jobId, address node)
        external
        view
        jobExists(jobId)
        returns (bool)
    {
        Job storage job = jobs[jobId];
        for (uint i = 0; i < job.assignedNodes.length; i++) {
            if (job.assignedNodes[i] == node) return true;
        }
        return false;
    }

    function setMinFee(uint256 _minFee) external onlyOwner {
        minFee = _minFee;
    }
}