// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================
// MPCToken.sol — MPC Network Utility Token
// ============================================
// This is the ERC-20 token that powers the
// entire MPC network economy.
//
// How it is used:
// - Nodes stake tokens to join the network
// - Clients pay tokens to submit jobs
// - Honest nodes earn tokens for completing jobs
// - Cheating nodes lose their staked tokens
//
// It is a standard ERC-20 with two extra features:
// 1. Minting — owner can create new tokens
// 2. Burning — tokens can be destroyed (slashing)
// ============================================

contract MPCToken {

    // ── ERC-20 standard state ──────────────────
    string public name = "MPC Network Token";
    string public symbol = "MPCT";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // owner of the contract (can mint tokens)
    address public owner;

    // balances of each address
    mapping(address => uint256) public balanceOf;

    // allowances: owner -> spender -> amount
    mapping(address => mapping(address => uint256)) public allowance;

    // ── Events ─────────────────────────────────
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 value
    );

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);

    // ── Modifiers ──────────────────────────────
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "MPCToken: caller is not owner"
        );
        _;
    }

    // ── Constructor ────────────────────────────
    // Sets the deployer as owner.
    // Mints initial supply to the deployer.
    constructor(uint256 initialSupply) {
        owner = msg.sender;
        _mint(msg.sender, initialSupply);
    }

    // ============================================
    // transfer — send tokens to another address
    // ============================================
    function transfer(
        address to,
        uint256 amount
    ) public returns (bool) {
        require(to != address(0), "MPCToken: transfer to zero address");
        require(
            balanceOf[msg.sender] >= amount,
            "MPCToken: insufficient balance"
        );

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // ============================================
    // approve — allow spender to spend your tokens
    // ============================================
    function approve(
        address spender,
        uint256 amount
    ) public returns (bool) {
        require(
            spender != address(0),
            "MPCToken: approve to zero address"
        );

        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // ============================================
    // transferFrom — spend approved tokens
    // ============================================
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        require(to != address(0), "MPCToken: transfer to zero address");
        require(
            balanceOf[from] >= amount,
            "MPCToken: insufficient balance"
        );
        require(
            allowance[from][msg.sender] >= amount,
            "MPCToken: insufficient allowance"
        );

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    // ============================================
    // mint — create new tokens (owner only)
    // ============================================
    // Used to reward honest nodes after
    // completing a computation job correctly.
    function mint(
        address to,
        uint256 amount
    ) public onlyOwner {
        _mint(to, amount);
    }

    // ============================================
    // burn — destroy tokens (slashing mechanism)
    // ============================================
    // Called by SlashingContract to penalise
    // cheating nodes. Tokens are permanently
    // removed from circulation.
    function burn(
        address from,
        uint256 amount
    ) public onlyOwner {
        require(
            balanceOf[from] >= amount,
            "MPCToken: burn amount exceeds balance"
        );
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Burn(from, amount);
        emit Transfer(from, address(0), amount);
    }

    // ============================================
    // transferOwnership — transfer contract control
    // ============================================
    function transferOwnership(
        address newOwner
    ) public onlyOwner {
        require(
            newOwner != address(0),
            "MPCToken: new owner is zero address"
        );
        owner = newOwner;
    }

    // ── Internal functions ─────────────────────

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "MPCToken: mint to zero address");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }
}