// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================
// StakingContract.sol — Node Stake Management
// ============================================
// Before a node can participate in MPC jobs,
// it must stake tokens here as collateral.
//
// Why staking matters:
// Without stake, a node has nothing to lose
// by cheating. With stake, cheating means
// losing real money. This aligns incentives.
//
// How it works:
// 1. Node calls stake() with token amount
// 2. Node is now eligible to accept jobs
// 3. If node cheats → SlashingContract calls
//    slash() → node loses their stake
// 4. If node wants to leave → calls unstake()
//    after a lockup period
// ============================================

import "./MPCToken.sol";

contract StakingContract {

    // ── Node status ───────────────────────────
    enum NodeStatus {
        Inactive,   // 0 — not staked
        Active,     // 1 — staked and ready
        Slashed,    // 2 — caught cheating
        Unstaking   // 3 — waiting to withdraw
    }

    // ── Node info ─────────────────────────────
    struct NodeInfo {
        address nodeAddress;
        uint256 stakedAmount;
        uint256 stakedAt;
        uint256 unstakeRequestedAt;
        NodeStatus status;
        uint256 jobsCompleted;
        uint256 jobsFailed;
        uint256 reputationScore;
    }

    // ── State ─────────────────────────────────
    MPCToken public token;
    address public owner;
    address public slashingContract;

    uint256 public minStake;
    uint256 public unstakeLockup;

    mapping(address => NodeInfo) public nodes;
    address[] public activeNodes;
    uint256 public totalStaked;

    // ── Events ────────────────────────────────
    event NodeStaked(address indexed node, uint256 amount);
    event NodeUnstakeRequested(
        address indexed node,
        uint256 amount,
        uint256 availableAt
    );
    event NodeUnstaked(address indexed node, uint256 amount);
    event NodeSlashed(
        address indexed node,
        uint256 amount,
        string reason
    );
    event ReputationUpdated(address indexed node, uint256 newScore);

    // ── Modifiers ─────────────────────────────
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "StakingContract: not owner"
        );
        _;
    }

    modifier onlySlasher() {
        require(
            msg.sender == slashingContract ||
            msg.sender == owner,
            "StakingContract: not authorized to slash"
        );
        _;
    }

    // ── Constructor ───────────────────────────
    constructor(
        address tokenAddress,
        uint256 _minStake,
        uint256 _unstakeLockup
    ) {
        owner = msg.sender;
        token = MPCToken(tokenAddress);
        minStake = _minStake;
        unstakeLockup = _unstakeLockup;
    }

    // ============================================
    // stake — node locks tokens to join network
    // ============================================
    function stake(uint256 amount) external {
        require(
            amount >= minStake,
            "StakingContract: below minimum stake"
        );
        require(
            nodes[msg.sender].status == NodeStatus.Inactive ||
            nodes[msg.sender].status == NodeStatus.Unstaking,
            "StakingContract: already staked"
        );

        require(
            token.transferFrom(msg.sender, address(this), amount),
            "StakingContract: transfer failed"
        );

        nodes[msg.sender] = NodeInfo({
            nodeAddress: msg.sender,
            stakedAmount: amount,
            stakedAt: block.timestamp,
            unstakeRequestedAt: 0,
            status: NodeStatus.Active,
            jobsCompleted: 0,
            jobsFailed: 0,
            reputationScore: 50
        });

        activeNodes.push(msg.sender);
        totalStaked += amount;

        emit NodeStaked(msg.sender, amount);
    }

    // ============================================
    // requestUnstake — begin the unstaking process
    // ============================================
    function requestUnstake() external {
        NodeInfo storage node = nodes[msg.sender];
        require(
            node.status == NodeStatus.Active,
            "StakingContract: node not active"
        );

        node.status = NodeStatus.Unstaking;
        node.unstakeRequestedAt = block.timestamp;

        uint256 availableAt = block.timestamp + unstakeLockup;

        emit NodeUnstakeRequested(
            msg.sender,
            node.stakedAmount,
            availableAt
        );
    }

    // ============================================
    // unstake — withdraw tokens after lockup
    // ============================================
    function unstake() external {
        NodeInfo storage node = nodes[msg.sender];
        require(
            node.status == NodeStatus.Unstaking,
            "StakingContract: not in unstaking state"
        );
        require(
            block.timestamp >= node.unstakeRequestedAt + unstakeLockup,
            "StakingContract: lockup period not over"
        );

        uint256 amount = node.stakedAmount;

        _removeActiveNode(msg.sender);

        node.stakedAmount = 0;
        node.status = NodeStatus.Inactive;
        totalStaked -= amount;

        token.transfer(msg.sender, amount);

        emit NodeUnstaked(msg.sender, amount);
    }

    // ============================================
    // slash — penalise a cheating node
    // ============================================
    // Tokens already held by this contract.
    // Transfer slashed amount to treasury (owner).
    // No burn call needed — avoids ownership issue.
    function slash(
        address nodeAddress,
        uint256 amount,
        string calldata reason
    ) external onlySlasher {
        NodeInfo storage node = nodes[nodeAddress];
        require(
            node.status == NodeStatus.Active ||
            node.status == NodeStatus.Unstaking,
            "StakingContract: node not slashable"
        );
        require(
            amount <= node.stakedAmount,
            "StakingContract: slash exceeds stake"
        );

        node.stakedAmount -= amount;
        node.status = NodeStatus.Slashed;
        node.reputationScore = 0;
        totalStaked -= amount;

        _removeActiveNode(nodeAddress);

        // Transfer slashed tokens to treasury
        // Tokens are already held by this contract
        token.transfer(owner, amount);

        emit NodeSlashed(nodeAddress, amount, reason);
    }

    // ============================================
    // recordJobCompleted — update node stats
    // ============================================
    function recordJobCompleted(address nodeAddress)
        external
        onlySlasher
    {
        NodeInfo storage node = nodes[nodeAddress];
        node.jobsCompleted++;

        if (node.reputationScore < 95) {
            node.reputationScore += 5;
        } else {
            node.reputationScore = 100;
        }

        emit ReputationUpdated(nodeAddress, node.reputationScore);
    }

    // ============================================
    // recordJobFailed — update node stats
    // ============================================
    function recordJobFailed(address nodeAddress)
        external
        onlySlasher
    {
        NodeInfo storage node = nodes[nodeAddress];
        node.jobsFailed++;

        if (node.reputationScore > 10) {
            node.reputationScore -= 10;
        } else {
            node.reputationScore = 0;
        }

        emit ReputationUpdated(nodeAddress, node.reputationScore);
    }

    // ── View functions ────────────────────────

    function isActiveNode(address nodeAddress)
        external view returns (bool)
    {
        return nodes[nodeAddress].status == NodeStatus.Active;
    }

    function getStake(address nodeAddress)
        external view returns (uint256)
    {
        return nodes[nodeAddress].stakedAmount;
    }

    function getReputation(address nodeAddress)
        external view returns (uint256)
    {
        return nodes[nodeAddress].reputationScore;
    }

    function getActiveNodeCount()
        external view returns (uint256)
    {
        return activeNodes.length;
    }

    function setSlashingContract(address _slashingContract)
        external onlyOwner
    {
        slashingContract = _slashingContract;
    }

    function setMinStake(uint256 _minStake) external onlyOwner {
        minStake = _minStake;
    }

    // ── Internal functions ────────────────────

    function _removeActiveNode(address nodeAddress) internal {
        for (uint i = 0; i < activeNodes.length; i++) {
            if (activeNodes[i] == nodeAddress) {
                activeNodes[i] = activeNodes[activeNodes.length - 1];
                activeNodes.pop();
                break;
            }
        }
    }
}