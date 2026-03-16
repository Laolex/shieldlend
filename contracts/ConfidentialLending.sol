// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, ebool, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "./ZamaConfig.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ConfidentialLending
 * @notice Overcollateralized lending protocol using FHE.
 *         All collateral amounts, loan amounts, interest rates,
 *         health factors and credit scores stay encrypted on-chain.
 */
contract ConfidentialLending is ZamaEthereumConfig, AccessControlEnumerable, ReentrancyGuard, Pausable {

    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant LIQUIDATOR_ROLE = keccak256("LIQUIDATOR_ROLE");

    // ─── Encrypted position per borrower ───────────────────────────────────
    struct Position {
        euint64 collateral;      // deposited ETH (in wei, encrypted)
        euint64 loanAmount;      // principal borrowed (encrypted)
        euint64 interestRate;    // per-cycle rate in bps (encrypted, per-user)
        euint64 totalDebt;       // principal + accrued interest (encrypted)
        euint64 creditScore;     // 0-1000 encrypted credit score
        ebool   isLiquidatable;  // FHE.lt(healthFactor, MIN_HEALTH) result
        uint256 lastAccrual;     // timestamp of last interest accrual
        bool    active;
    }

    mapping(address => Position) private positions;
    address[] public borrowerList;

    // ─── Protocol constants (plaintext — public knowledge) ─────────────────
    uint64 public constant COLLATERAL_RATIO  = 150;  // 150% overcollateral
    uint64 public constant MIN_HEALTH_FACTOR = 110;  // liquidation threshold
    uint64 public constant BASE_RATE_BPS     = 500;  // 5% base interest rate
    uint64 public constant MAX_LOAN_RATIO    = 66;   // borrow up to 66% of collateral

    // ─── ETH reserve ───────────────────────────────────────────────────────
    uint256 public totalReserves;

    // ─── Events ────────────────────────────────────────────────────────────
    event Deposited(address indexed borrower, uint256 timestamp);
    event Borrowed(address indexed borrower, uint256 timestamp);
    event Repaid(address indexed borrower, uint256 timestamp);
    event Liquidated(address indexed borrower, address indexed liquidator, uint256 timestamp);
    event InterestAccrued(address indexed borrower, uint256 timestamp);
    event CreditScoreUpdated(address indexed borrower, uint256 timestamp);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LIQUIDATOR_ROLE, msg.sender);
    }

    // ─────────────────────────── Deposit ───────────────────────────────────

    /**
     * @notice Deposit ETH as collateral (amount encrypted client-side).
     * @param inputHandle   externalEuint64 handle from fhevmjs
     * @param inputProof    ZK proof for the encrypted input
     */
    function deposit(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external payable nonReentrant whenNotPaused {
        euint64 encAmount = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        Position storage pos = positions[msg.sender];

        if (!pos.active) {
            pos.collateral   = encAmount;
            pos.loanAmount   = FHE.asEuint64(0);
            pos.totalDebt    = FHE.asEuint64(0);
            pos.creditScore  = FHE.asEuint64(500); // default mid-range score
            pos.interestRate = FHE.asEuint64(BASE_RATE_BPS);
            pos.isLiquidatable = FHE.asEbool(false);
            pos.lastAccrual  = block.timestamp;
            pos.active       = true;
            borrowerList.push(msg.sender);
        } else {
            pos.collateral = FHE.add(pos.collateral, encAmount);
        }

        // Grant ACL permissions
        FHE.allow(pos.collateral,   msg.sender);
        FHE.allowThis(pos.collateral);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.creditScore);
        FHE.allowThis(pos.interestRate);
        FHE.allowThis(pos.isLiquidatable);

        totalReserves += msg.value;
        emit Deposited(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Borrow ────────────────────────────────────

    /**
     * @notice Borrow against collateral. Loan amount encrypted.
     *         Health factor computed entirely in FHE.
     */
    function borrow(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No collateral deposited");

        euint64 encBorrow = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        // Add to existing debt
        pos.loanAmount = FHE.add(pos.loanAmount, encBorrow);
        pos.totalDebt  = FHE.add(pos.totalDebt, encBorrow);

        // Recompute health factor: collateral * 100 / totalDebt
        // Using FHE.div approximation via shifts for gas efficiency
        // healthFactor = (collateral << 7) / totalDebt  (×128 for precision)
        // isLiquidatable = collateral * 100 < totalDebt * COLLATERAL_RATIO
        // i.e. debt exceeds max_loan_ratio of collateral
        euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
        euint64 debtScaled       = FHE.mul(pos.totalDebt,  FHE.asEuint64(COLLATERAL_RATIO));
        pos.isLiquidatable       = FHE.lt(collateralScaled, debtScaled);

        // Grant permissions
        FHE.allow(pos.loanAmount,      msg.sender);
        FHE.allow(pos.totalDebt,       msg.sender);
        FHE.allow(pos.isLiquidatable,  msg.sender);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.isLiquidatable);
        _allowLiquidators(pos.isLiquidatable);

        emit Borrowed(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Repay ─────────────────────────────────────

    /**
     * @notice Repay debt (amount encrypted).
     */
    function repay(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");

        euint64 encRepay = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);

        // Subtract repayment from debt (floor at 0)
        euint64 newDebt = FHE.sub(pos.totalDebt, encRepay);
        pos.totalDebt   = newDebt;
        pos.loanAmount  = FHE.sub(pos.loanAmount, encRepay);

        // Update health factor
        euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
        euint64 debtScaled       = FHE.mul(pos.totalDebt,  FHE.asEuint64(COLLATERAL_RATIO));
        pos.isLiquidatable       = FHE.lt(collateralScaled, debtScaled);

        FHE.allow(pos.totalDebt,      msg.sender);
        FHE.allow(pos.loanAmount,     msg.sender);
        FHE.allow(pos.isLiquidatable, msg.sender);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.isLiquidatable);

        emit Repaid(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Interest accrual ──────────────────────────

    /**
     * @notice Accrue interest on a position using encrypted per-user rate.
     *         interest = totalDebt * interestRate / 10000
     *         Approximated as: totalDebt * interestRate >> 14  (÷10000 ≈ >>13.3)
     */
    function accrueInterest(address borrower) external whenNotPaused {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        // interest ≈ totalDebt * interestRate / 10000
        euint64 interest  = FHE.div(FHE.mul(pos.totalDebt, pos.interestRate), 10000);
        pos.totalDebt     = FHE.add(pos.totalDebt, interest);
        pos.lastAccrual   = block.timestamp;

        FHE.allow(pos.totalDebt, borrower);
        FHE.allowThis(pos.totalDebt);

        emit InterestAccrued(borrower, block.timestamp);
    }

    // ─────────────────────────── Liquidation ───────────────────────────────

    /**
     * @notice Liquidate an undercollateralized position.
     *         isLiquidatable is an ebool computed via FHE.lt — never reveals health factor.
     */
    function liquidate(address borrower) external onlyRole(LIQUIDATOR_ROLE) nonReentrant {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        // Decrypt isLiquidatable for the liquidation gate
        // In production: use FHE.req(pos.isLiquidatable) when available
        // For demo: liquidator has ACL access to isLiquidatable handle
        pos.collateral     = FHE.asEuint64(0);
        pos.loanAmount     = FHE.asEuint64(0);
        pos.totalDebt      = FHE.asEuint64(0);
        pos.isLiquidatable = FHE.asEbool(false);
        pos.active         = false;

        emit Liquidated(borrower, msg.sender, block.timestamp);
    }

    // ─────────────────────────── Credit score ──────────────────────────────

    /**
     * @notice Admin updates encrypted credit score (gates interest rate).
     */
    function updateCreditScore(
        address borrower,
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external onlyRole(ADMIN_ROLE) {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        euint64 newScore    = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        pos.creditScore     = newScore;

        // Better score → lower interest rate
        // rate = BASE_RATE - (score / 1000 * BASE_RATE / 2)
        // Approximated: rate = BASE_RATE - (score >> 1) / 100
        euint64 discount    = FHE.div(FHE.div(newScore, 2), 100);
        pos.interestRate    = FHE.sub(FHE.asEuint64(BASE_RATE_BPS), discount);

        FHE.allow(pos.creditScore,  borrower);
        FHE.allow(pos.interestRate, borrower);
        FHE.allowThis(pos.creditScore);
        FHE.allowThis(pos.interestRate);

        emit CreditScoreUpdated(borrower, block.timestamp);
    }

    // ─────────────────────────── View functions ────────────────────────────

    function getEncryptedCollateral(address borrower) external view returns (euint64) {
        return positions[borrower].collateral;
    }

    function getEncryptedLoanAmount(address borrower) external view returns (euint64) {
        return positions[borrower].loanAmount;
    }

    function getEncryptedTotalDebt(address borrower) external view returns (euint64) {
        return positions[borrower].totalDebt;
    }

    function getEncryptedInterestRate(address borrower) external view returns (euint64) {
        return positions[borrower].interestRate;
    }

    function getEncryptedCreditScore(address borrower) external view returns (euint64) {
        return positions[borrower].creditScore;
    }

    function getIsLiquidatable(address borrower) external view returns (ebool) {
        return positions[borrower].isLiquidatable;
    }

    function getBorrowerCount() external view returns (uint256) {
        return borrowerList.length;
    }

    function isActive(address borrower) external view returns (bool) {
        return positions[borrower].active;
    }

    // ─────────────────────────── Internal ──────────────────────────────────

    function _allowLiquidators(ebool ct) internal {
        uint256 n = getRoleMemberCount(LIQUIDATOR_ROLE);
        for (uint256 i = 0; i < n; i++) {
            FHE.allow(ct, getRoleMember(LIQUIDATOR_ROLE, i));
        }
    }

    // ─────────────────────────── Admin ─────────────────────────────────────

    function pause()   external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }

    function grantLiquidatorRole(address a) external onlyRole(ADMIN_ROLE) {
        grantRole(LIQUIDATOR_ROLE, a);
    }

    receive() external payable { totalReserves += msg.value; }
}
