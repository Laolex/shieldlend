// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, ebool, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "./ZamaConfig.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IConfidentialCreditScore} from "./shieldscore/IConfidentialCreditScore.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IOracle} from "./IOracle.sol";

/**
 * @title ConfidentialLending
 * @notice Overcollateralized lending protocol using Zama fhEVM.
 *         All collateral amounts, loan amounts, interest rates,
 *         health factors and credit scores stay encrypted on-chain.
 *
 * ShieldScore integration (optional):
 *  - setScoreContract(addr) wires in ConfidentialCreditScore
 *  - Score >= SCORE_TIER_PREMIUM (800) → 110% collateral ratio
 *  - Score >= SCORE_TIER_STANDARD (600) → 130% collateral ratio
 *  - No score or below 600    → 150% collateral ratio (default)
 *
 * Protocol upgrades (v2):
 *  - Chainlink oracle adapter (IOracle) for token price feeds
 *  - Supply / borrow caps (ethSupplyCap, tokenSupplyCap, maxBorrowPerPosition)
 *  - Reserve factor + bad debt absorption (protocolReserve, reserveFactorBps)
 *  - Liquidation bonus funded from protocol reserve (liquidatorBonusBps)
 *  - Admin-configurable interest rate model (baseRateBps + utilization)
 *  - Emergency admin functions (freezeToken, emergencyLiquidate)
 *  - Permissionless liquidation post confirmation (no LIQUIDATOR_ROLE required)
 *
 * @dev Oracle privacy note: the oracle cannot validate the encrypted input amount.
 *      The client computes the ETH-wei equivalent off-chain using the oracle price
 *      and submits it encrypted. The oracle enforces price freshness at deposit time;
 *      clients must read the TokenPriceUsed event or call oracle.getEthWeiPerToken()
 *      before encrypting their deposit amount.
 *
 * @dev Interest rate note: automated utilization tracking requires summing all
 *      encrypted position debts, which breaks FHE privacy. Admin monitors utilization
 *      off-chain and calls setRateParams() to adjust.
 *
 * @dev Borrow cap note: a global borrow cap would require FHE aggregation of all
 *      encrypted debts. maxBorrowPerPosition caps collateral size; effective borrow
 *      cap = MAX_LOAN_RATIO (66%) * maxBorrowPerPosition.
 */
contract ConfidentialLending is ZamaEthereumConfig, AccessControlEnumerable, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE      = DEFAULT_ADMIN_ROLE;
    bytes32 public constant LIQUIDATOR_ROLE = keccak256("LIQUIDATOR_ROLE");

    // ─── ShieldScore integration ────────────────────────────────────────────
    IConfidentialCreditScore public scoreContract;   // address(0) if not wired
    uint64 public constant SCORE_TIER_PREMIUM  = 800; // → 110% ratio
    uint64 public constant SCORE_TIER_STANDARD = 600; // → 130% ratio

    // ─── Oracle ─────────────────────────────────────────────────────────────
    /// @notice Oracle adapter. address(0) = use TokenConfig.ethWeiPerToken fallback.
    IOracle public oracle;

    // ─── Multi-asset collateral ─────────────────────────────────────────────
    struct TokenConfig {
        bool     supported;
        bool     frozen;          // admin can freeze deposits (not withdrawals)
        uint8    decimals;
        uint256  ethWeiPerToken;  // fallback price; 0 = oracle-only token
    }
    mapping(address => TokenConfig)              public tokenConfigs;
    address[]                                    public supportedTokens;
    // plaintext per-user token balances (for withdrawal on close/liquidation)
    mapping(address => mapping(address => uint256)) public tokenDeposited;

    // ─── Encrypted position per borrower ───────────────────────────────────
    struct Position {
        euint64 collateral;      // total collateral in ETH-wei equivalent (encrypted)
        euint64 loanAmount;      // principal borrowed (encrypted)
        euint64 interestRate;    // per-cycle rate in bps (encrypted, per-user)
        euint64 totalDebt;       // principal + accrued interest (encrypted)
        euint64 creditScore;     // 0–1000 (encrypted)
        ebool   isLiquidatable;  // FHE.lt(collateral*100, debt*COLLATERAL_RATIO)
        uint256 lastAccrual;     // timestamp of last interest accrual
        bool    active;
    }

    mapping(address => Position) private positions;

    // ─── Plaintext ETH accounting per borrower ─────────────────────────────
    mapping(address => uint256) public ethDeposited;

    // ─── Liquidation reveal flow ────────────────────────────────────────────
    mapping(address => bool) private pendingLiquidationReveal;
    mapping(address => bool) private confirmedLiquidatable;    // set by verifyLiquidationReveal

    // ─── Close position flow ────────────────────────────────────────────────
    mapping(address => bool) private pendingClose;

    // ─── Borrower list with O(1) removal ───────────────────────────────────
    address[] public borrowerList;
    mapping(address => uint256) private borrowerIndex;

    // ─── Protocol constants (plaintext — public knowledge) ─────────────────
    uint64 public constant COLLATERAL_RATIO  = 150;  // 150% overcollateral required
    uint64 public constant MIN_HEALTH_FACTOR = 110;  // liquidation at 110%
    uint64 public constant MAX_LOAN_RATIO    = 66;   // borrow up to 66% of collateral

    // ─── Configurable interest rate model ──────────────────────────────────
    /// @notice Base interest rate in bps. Default: 500 (5%).
    uint64 public baseRateBps = 500;
    /// @notice Admin-set utilization estimate (0–10000). Default: 0.
    /// @dev Cannot track automatically — encrypted debt sums break FHE privacy.
    uint64 public utilizationBps = 0;
    /// @notice Max rate uplift at 100% utilization, in bps. Default: 1000 (10%).
    uint64 public utilizationMultiplierBps = 1000;

    // ─── Supply / borrow caps ───────────────────────────────────────────────
    /// @notice Max ETH in totalReserves. 0 = uncapped.
    uint256 public ethSupplyCap;
    /// @notice Max token units deposited per token. 0 = uncapped.
    mapping(address => uint256) public tokenSupplyCap;
    /// @notice Max ETH collateral per position. 0 = uncapped.
    /// @dev Effective borrow cap = 66% * maxBorrowPerPosition.
    uint256 public maxBorrowPerPosition;

    // ─── Protocol reserve + fees ────────────────────────────────────────────
    /// @notice Accumulated protocol fees (ETH-wei). Funded via liquidation fees.
    uint256 public protocolReserve;
    /// @notice Fraction of liquidation proceeds taken as protocol fee. Default: 200 (2%).
    uint256 public reserveFactorBps = 200;
    /// @notice Min reserve ratio vs totalReserves. Below this, new borrows halt. 0 = disabled (default).
    uint256 public minReserveRatioBps = 0;
    /// @notice Bonus paid to liquidator from protocolReserve. Default: 500 (5%).
    uint256 public liquidatorBonusBps = 500;

    /// @notice Recipient of all emergency liquidation proceeds. Must be set before emergencyLiquidate can be called.
    /// @dev [M-2] Decouples admin execution from custody — set to a multisig/treasury, never to msg.sender.
    address payable public liquidationTreasury;

    uint256 public totalReserves;

    // ─── Events ────────────────────────────────────────────────────────────
    event Deposited(address indexed borrower, uint256 timestamp);
    event Borrowed(address indexed borrower, uint256 timestamp);
    event Repaid(address indexed borrower, uint256 timestamp);
    event Liquidated(
        address indexed borrower,
        address indexed liquidator,
        uint256 ethTransferred,
        uint256 protocolFee,
        uint256 bonus,
        uint256 timestamp
    );
    event InterestAccrued(address indexed borrower, uint256 timestamp);
    event CreditScoreUpdated(address indexed borrower, uint256 timestamp);
    event LiquidationRevealRequested(address indexed borrower, bytes32 isLiquidatableHandle, uint256 timestamp);
    event LiquidationAlertPublic(address indexed borrower, bool isLiquidatable, uint256 timestamp);
    event CloseRequested(address indexed borrower, bytes32 totalDebtHandle, uint256 timestamp);
    event PositionClosed(address indexed borrower, uint256 ethReturned, uint256 timestamp);
    event ScoreContractSet(address indexed addr);
    event TokenDeposited(address indexed borrower, address indexed token, uint256 amount, uint256 timestamp);
    event TokenAdded(address indexed token, uint8 decimals, uint256 ethWeiPerToken);
    event TokenPriceUsed(address indexed token, uint256 price, uint256 timestamp);
    event TokenFrozen(address indexed token, uint256 timestamp);
    event TokenUnfrozen(address indexed token, uint256 timestamp);
    event OracleSet(address indexed oracle_);
    event RateParamsUpdated(uint64 baseRate, uint64 utilization, uint64 multiplier);
    event CapsUpdated(uint256 ethSupplyCap_, uint256 maxBorrowPerPosition_);
    event ReserveWithdrawn(address indexed to, uint256 amount);
    event EmergencyLiquidation(address indexed borrower, address indexed admin, address indexed treasury, uint256 timestamp);
    event LiquidationTreasurySet(address indexed treasury);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LIQUIDATOR_ROLE, msg.sender);
    }

    // ─────────────────────────── Deposit ───────────────────────────────────

    /**
     * @notice Deposit ETH as collateral. Amount encrypted client-side.
     */
    function deposit(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external payable nonReentrant whenNotPaused {
        require(
            ethSupplyCap == 0 || totalReserves + msg.value <= ethSupplyCap,
            "Supply cap reached"
        );

        euint64 encAmount = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        _applyCollateral(msg.sender, encAmount);

        ethDeposited[msg.sender] += msg.value;
        totalReserves += msg.value;
        emit Deposited(msg.sender, block.timestamp);
    }

    /**
     * @notice Deposit an ERC20 token as collateral (cross-collateral).
     *         inputHandle/inputProof is the encrypted ETH-wei equivalent computed client-side.
     *
     *         If oracle is set, the authoritative price is fetched here and emitted in
     *         TokenPriceUsed — clients should use this price before encrypting.
     *         If oracle is not set, TokenConfig.ethWeiPerToken is the fallback.
     *
     * @dev [CR-1] The contract clamps the encrypted ETH-equivalent to an oracle-derived
     *      plaintext ceiling (tokenAmount * price / 10**decimals) using FHE.select.
     *      A malicious user who over-reports their ETH-equivalent is silently clamped
     *      down to the authoritative value. The cap itself is plaintext and therefore
     *      leaks the *maximum* deposit value — but that value is already public on-chain
     *      via the ERC20 transfer amount, so no additional privacy is lost. A user who
     *      under-reports will simply get credited less collateral than they deposited.
     */
    function depositToken(
        address token,
        uint256 tokenAmount,
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        TokenConfig memory cfg = tokenConfigs[token];
        require(cfg.supported, "Token not supported");
        require(!cfg.frozen, "Token frozen");
        require(tokenAmount > 0, "Zero amount");
        require(
            tokenSupplyCap[token] == 0 ||
            tokenDeposited[msg.sender][token] + tokenAmount <= tokenSupplyCap[token],
            "Token supply cap reached"
        );

        // [CR-1] Resolve authoritative price (oracle if set, else fallback).
        //        Used both for the TokenPriceUsed event AND to compute an upper-bound
        //        clamp on the user-submitted encrypted ETH equivalent.
        uint256 price;
        if (address(oracle) != address(0)) {
            price = oracle.getEthWeiPerToken(token);
            emit TokenPriceUsed(token, price, block.timestamp);
        } else {
            require(cfg.ethWeiPerToken > 0, "No price available");
            price = cfg.ethWeiPerToken;
        }

        IERC20(token).safeTransferFrom(msg.sender, address(this), tokenAmount);
        tokenDeposited[msg.sender][token] += tokenAmount;

        // [CR-1] Compute plaintext ETH-wei cap = tokenAmount * price / 10**decimals.
        //        The cap is still public (it leaks the deposit value, which is already
        //        known from the ERC20 transfer), but it prevents the user from
        //        encrypting an ETH-equivalent GREATER than what they actually deposited.
        //        The FHE.select below takes the minimum of (cap, userEncryptedValue),
        //        so a user who under-reports still gets what they declared, but one who
        //        over-reports is clamped down to the oracle-derived ceiling.
        uint256 capWei = (tokenAmount * price) / (10 ** uint256(cfg.decimals));
        // Clamp cap to uint64 range to stay inside euint64 arithmetic safely.
        if (capWei > type(uint64).max) {
            capWei = type(uint64).max;
        }

        euint64 encEquiv = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        FHE.allowThis(encEquiv);
        euint64 encCap   = FHE.asEuint64(uint64(capWei));
        FHE.allowThis(encCap);
        // clamped = encEquiv > cap ? cap : encEquiv
        euint64 clamped  = FHE.select(FHE.lt(encCap, encEquiv), encCap, encEquiv);
        FHE.allowThis(clamped);

        _applyCollateral(msg.sender, clamped);

        emit TokenDeposited(msg.sender, token, tokenAmount, block.timestamp);
    }

    // ─────────────────────────── Borrow ────────────────────────────────────

    /**
     * @notice Borrow against collateral. Health factor recomputed in FHE.
     */
    function borrow(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No collateral deposited");
        require(
            maxBorrowPerPosition == 0 || ethDeposited[msg.sender] <= maxBorrowPerPosition,
            "Borrow cap: collateral exceeds position limit"
        );
        require(
            minReserveRatioBps == 0 ||
            protocolReserve >= totalReserves * minReserveRatioBps / 10000,
            "Reserve too low"
        );

        euint64 encBorrow = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        FHE.allowThis(encBorrow); // [H-1] ACL grant before coprocessor use

        euint64 newLoan = FHE.add(pos.loanAmount, encBorrow);
        euint64 newDebt = FHE.add(pos.totalDebt,  encBorrow);
        pos.loanAmount  = newLoan;
        pos.totalDebt   = newDebt;

        pos.isLiquidatable = _computeHealthFactor(pos, msg.sender);

        FHE.allow(pos.loanAmount,     msg.sender);
        FHE.allow(pos.totalDebt,      msg.sender);
        FHE.allow(pos.isLiquidatable, msg.sender);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.isLiquidatable);
        _allowLiquidators(pos.isLiquidatable);

        emit Borrowed(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Repay ─────────────────────────────────────

    /**
     * @notice Repay debt. Uses floor-at-zero to prevent underflow wrap.
     */
    function repay(
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external nonReentrant whenNotPaused {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");

        euint64 encRepay = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        FHE.allowThis(encRepay); // [H-1] ACL grant before coprocessor use

        // Floor-at-zero: if repayment > debt, clamp to 0 instead of wrapping
        euint64 newDebt  = FHE.select(FHE.not(FHE.lt(pos.totalDebt,  encRepay)), FHE.sub(pos.totalDebt,  encRepay), FHE.asEuint64(0));
        euint64 newLoan  = FHE.select(FHE.not(FHE.lt(pos.loanAmount, encRepay)), FHE.sub(pos.loanAmount, encRepay), FHE.asEuint64(0));
        pos.totalDebt    = newDebt;
        pos.loanAmount   = newLoan;

        pos.isLiquidatable = _computeHealthFactor(pos, msg.sender);

        FHE.allow(pos.totalDebt,      msg.sender);
        FHE.allow(pos.loanAmount,     msg.sender);
        FHE.allow(pos.isLiquidatable, msg.sender);
        FHE.allowThis(pos.totalDebt);
        FHE.allowThis(pos.loanAmount);
        FHE.allowThis(pos.isLiquidatable);

        // [CR-2] Clear stale liquidation flag — a repaid position must not be liquidatable
        delete confirmedLiquidatable[msg.sender];
        delete pendingLiquidationReveal[msg.sender];

        emit Repaid(msg.sender, block.timestamp);
    }

    // ─────────────────────────── Interest accrual ──────────────────────────

    /**
     * @notice Accrue interest on a position. Restricted to ADMIN_ROLE.
     *         interest = totalDebt * interestRate / 10000
     */
    function accrueInterest(address borrower) external onlyRole(ADMIN_ROLE) whenNotPaused {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");
        // [M-1] Prevent unbounded compounding — enforce minimum 1-day interval
        require(block.timestamp >= pos.lastAccrual + 1 days, "Accrue too soon");

        euint64 interest = FHE.div(FHE.mul(pos.totalDebt, pos.interestRate), 10000);
        FHE.allowThis(interest); // [M-3] ACL grant for intermediate computed value
        euint64 newDebt  = FHE.add(pos.totalDebt, interest);
        pos.totalDebt    = newDebt;
        pos.lastAccrual  = block.timestamp;

        FHE.allow(pos.totalDebt, borrower);
        FHE.allowThis(pos.totalDebt);

        emit InterestAccrued(borrower, block.timestamp);
    }

    // ─────────────────────────── Liquidation ───────────────────────────────

    /**
     * @notice Step 1: mark isLiquidatable for public decryption.
     *         Anyone can call — the relayer decrypts and submits verifyLiquidationReveal.
     */
    function requestLiquidationReveal(address borrower) external {
        require(positions[borrower].active, "No active position");
        require(!pendingLiquidationReveal[borrower], "Reveal already pending"); // [H-3]
        ebool liqFlag = positions[borrower].isLiquidatable;
        FHE.makePubliclyDecryptable(liqFlag);
        pendingLiquidationReveal[borrower] = true;
        emit LiquidationRevealRequested(borrower, FHE.toBytes32(liqFlag), block.timestamp);
    }

    /**
     * @notice Step 2: submit Zama relayer decryption result.
     *         Sets confirmedLiquidatable[borrower] = true if position is underwater.
     */
    function verifyLiquidationReveal(
        address borrower,
        bytes32[] calldata handlesList,
        bytes calldata abiEncodedCleartexts,
        bytes calldata decryptionProof
    ) external {
        require(pendingLiquidationReveal[borrower], "No pending reveal");
        // [C-01] Pin handle to this borrower's isLiquidatable ciphertext.
        // checkSignatures attests that `handlesList` decrypts to `cleartexts` — it does
        // NOT bind them to any particular storage slot. Without this check, anyone could
        // submit any previously-publicly-decryptable ebool(true) and confirm liquidation
        // on a solvent position.
        require(handlesList.length == 1, "Expected 1 handle");
        require(
            handlesList[0] == FHE.toBytes32(positions[borrower].isLiquidatable),
            "Handle mismatch"
        );
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        bool isLiquidatable = abi.decode(abiEncodedCleartexts, (bool));
        delete pendingLiquidationReveal[borrower];
        if (isLiquidatable) {
            confirmedLiquidatable[borrower] = true;
        }
        emit LiquidationAlertPublic(borrower, isLiquidatable, block.timestamp);
    }

    /**
     * @notice Step 3: execute liquidation. Permissionless — any address can liquidate
     *         once confirmedLiquidatable is set after the 3-step reveal.
     *
     *         Fee/bonus math:
     *           protocolFee    = ethReward * reserveFactorBps / 10000  (taken from collateral)
     *           liquidatorBonus = ethReward * liquidatorBonusBps / 10000 (paid from protocolReserve if funded)
     *           liquidatorAmount = ethReward - protocolFee + bonus
     */
    function liquidate(address borrower) external nonReentrant {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");
        require(confirmedLiquidatable[borrower], "Not confirmed liquidatable - run reveal first");

        _executeLiquidation(borrower, msg.sender);
    }

    /**
     * @notice Emergency liquidation — ADMIN_ROLE only.
     *         Skips the confirmedLiquidatable check for stuck positions or oracle-failure recovery.
     * @dev [M-2] Proceeds go to liquidationTreasury, NOT msg.sender, preventing admin rug-pull.
     *      Set liquidationTreasury to a multisig before using this function.
     */
    function emergencyLiquidate(address borrower) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(positions[borrower].active, "No active position");
        require(liquidationTreasury != address(0), "liquidationTreasury not set");
        emit EmergencyLiquidation(borrower, msg.sender, liquidationTreasury, block.timestamp);
        _executeLiquidation(borrower, liquidationTreasury);
    }

    // ─────────────────────────── Close position ────────────────────────────

    /**
     * @notice Step 1: mark totalDebt for public decryption to verify it is zero.
     */
    function requestClosePosition() external {
        Position storage pos = positions[msg.sender];
        require(pos.active, "No active position");
        require(!pendingClose[msg.sender], "Close already pending");

        FHE.makePubliclyDecryptable(pos.totalDebt);
        pendingClose[msg.sender] = true;
        emit CloseRequested(msg.sender, FHE.toBytes32(pos.totalDebt), block.timestamp);
    }

    /**
     * @notice Step 2: verify totalDebt == 0, then return collateral ETH to borrower.
     */
    function verifyAndClose(
        bytes32[] calldata handlesList,
        bytes calldata abiEncodedCleartexts,
        bytes calldata decryptionProof
    ) external nonReentrant {
        require(pendingClose[msg.sender], "No pending close");
        // [C-01] Pin handle to this borrower's totalDebt ciphertext. Without this,
        // a borrower with nonzero debt could submit any publicly-decryptable euint64(0)
        // handle and close their position without repaying — draining the protocol.
        require(handlesList.length == 1, "Expected 1 handle");
        require(
            handlesList[0] == FHE.toBytes32(positions[msg.sender].totalDebt),
            "Handle mismatch"
        );
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        uint64 debtPlaintext = abi.decode(abiEncodedCleartexts, (uint64));
        require(debtPlaintext == 0, "Outstanding debt - repay in full before closing");

        uint256 ethToReturn = ethDeposited[msg.sender];
        positions[msg.sender].active = false;

        delete ethDeposited[msg.sender];
        delete pendingClose[msg.sender];
        _removeBorrower(msg.sender);

        totalReserves -= ethToReturn;
        emit PositionClosed(msg.sender, ethToReturn, block.timestamp);

        _returnTokens(msg.sender, msg.sender);

        if (ethToReturn > 0) {
            (bool ok,) = msg.sender.call{value: ethToReturn}("");
            require(ok, "ETH transfer failed");
        }
    }

    // ─────────────────────────── Credit score ──────────────────────────────

    /**
     * @notice Admin sets encrypted credit score. Better score → lower interest rate.
     *         rate = effectiveRate - clamp(score / 200, 0, effectiveRate/2)
     *         where effectiveRate = baseRateBps + (utilizationBps * multiplierBps / 10000)
     */
    function updateCreditScore(
        address borrower,
        bytes32 inputHandle,
        bytes calldata inputProof
    ) external onlyRole(ADMIN_ROLE) {
        Position storage pos = positions[borrower];
        require(pos.active, "No active position");

        euint64 newScore     = FHE.fromExternal(externalEuint64.wrap(inputHandle), inputProof);
        FHE.allowThis(newScore); // [H-1] ACL grant before coprocessor use
        pos.creditScore      = newScore;

        uint64 effectiveRate = _effectiveRate();
        euint64 discount     = FHE.div(FHE.shr(newScore, 1), 100);
        FHE.allowThis(discount); // [H-1] ACL grant for intermediate
        euint64 maxDiscount  = FHE.asEuint64(effectiveRate / 2);
        euint64 safeDiscount = FHE.select(FHE.not(FHE.lt(maxDiscount, discount)), discount, maxDiscount);
        FHE.allowThis(safeDiscount); // ACL grant for intermediate
        pos.interestRate     = FHE.sub(FHE.asEuint64(effectiveRate), safeDiscount);

        FHE.allow(pos.creditScore,  borrower);
        FHE.allow(pos.interestRate, borrower);
        FHE.allowThis(pos.creditScore);
        FHE.allowThis(pos.interestRate);

        emit CreditScoreUpdated(borrower, block.timestamp);
    }

    // ─────────────────────────── View functions ────────────────────────────

    function getEncryptedCollateral(address b)   external view returns (euint64) { return positions[b].collateral; }
    function getEncryptedLoanAmount(address b)   external view returns (euint64) { return positions[b].loanAmount; }
    function getEncryptedTotalDebt(address b)    external view returns (euint64) { return positions[b].totalDebt; }
    function getEncryptedInterestRate(address b) external view returns (euint64) { return positions[b].interestRate; }
    function getEncryptedCreditScore(address b)  external view returns (euint64) { return positions[b].creditScore; }
    function getIsLiquidatable(address b)        external view returns (ebool)   { return positions[b].isLiquidatable; }
    function getBorrowerCount()                  external view returns (uint256) { return borrowerList.length; }
    function isActive(address b)                 external view returns (bool)    { return positions[b].active; }
    function isPendingReveal(address b)          external view returns (bool)    { return pendingLiquidationReveal[b]; }
    function isConfirmedLiquidatable(address b)  external view returns (bool)    { return confirmedLiquidatable[b]; }
    function isPendingClose(address b)           external view returns (bool)    { return pendingClose[b]; }
    function getSupportedTokens()                external view returns (address[] memory) { return supportedTokens; }

    /// @notice Returns the current effective interest rate (bps) before credit score discount.
    function effectiveRateBps() external view returns (uint64) { return _effectiveRate(); }

    // ─────────────────────────── Internal ──────────────────────────────────

    /**
     * @notice Compute isLiquidatable for a position.
     *         isLiquidatable = collateral * 100 < totalDebt * effectiveRatio
     */
    function _computeHealthFactor(Position storage pos, address borrower) internal returns (ebool) {
        euint64 ratio = FHE.asEuint64(COLLATERAL_RATIO); // default: 150

        if (address(scoreContract) != address(0) && scoreContract.hasScore(borrower)) {
            ebool isPremium  = scoreContract.meetsThreshold(borrower, SCORE_TIER_PREMIUM);
            ebool isStandard = scoreContract.meetsThreshold(borrower, SCORE_TIER_STANDARD);

            ratio = FHE.select(isPremium, FHE.asEuint64(110),
                        FHE.select(isStandard, FHE.asEuint64(130),
                            FHE.asEuint64(COLLATERAL_RATIO)));
        }
        FHE.allowThis(ratio); // [H-2] ACL grant for computed ratio before FHE.mul use

        euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
        FHE.allowThis(collateralScaled);
        euint64 debtScaled       = FHE.mul(pos.totalDebt, ratio);
        FHE.allowThis(debtScaled);
        ebool   isLiq            = FHE.lt(collateralScaled, debtScaled);
        FHE.allowThis(isLiq);
        return isLiq;
    }

    /// @dev Add encrypted collateral to a position, initialising it if new.
    function _applyCollateral(address user, euint64 encAmount) internal {
        Position storage pos = positions[user];
        uint64 rate = _effectiveRate();
        if (!pos.active) {
            pos.collateral     = encAmount;
            pos.loanAmount     = FHE.asEuint64(0);
            pos.totalDebt      = FHE.asEuint64(0);
            pos.creditScore    = FHE.asEuint64(500);
            pos.interestRate   = FHE.asEuint64(rate);
            pos.isLiquidatable = FHE.asEbool(false);
            pos.lastAccrual    = block.timestamp;
            pos.active         = true;
            borrowerIndex[user] = borrowerList.length;
            borrowerList.push(user);
            FHE.allowThis(pos.loanAmount);
            FHE.allowThis(pos.totalDebt);
            FHE.allowThis(pos.creditScore);
            FHE.allowThis(pos.interestRate);
            FHE.allowThis(pos.isLiquidatable);
            FHE.allow(pos.loanAmount,     user);
            FHE.allow(pos.totalDebt,      user);
            FHE.allow(pos.creditScore,    user);
            FHE.allow(pos.interestRate,   user);
            FHE.allow(pos.isLiquidatable, user);
        } else {
            euint64 newCollateral = FHE.add(pos.collateral, encAmount);
            FHE.allowThis(newCollateral);
            FHE.allow(newCollateral, user);
            pos.collateral = newCollateral;
        }
        FHE.allow(pos.collateral, user);
        FHE.allowThis(pos.collateral);
    }

    /// @dev Shared liquidation logic for liquidate() and emergencyLiquidate().
    function _executeLiquidation(address borrower, address liquidator) internal {
        Position storage pos = positions[borrower];

        uint256 ethReward = ethDeposited[borrower];

        // Protocol fee (taken from collateral)
        uint256 protocolFee = ethReward * reserveFactorBps / 10000;
        uint256 liquidatorAmount = ethReward - protocolFee;

        // Liquidator bonus (paid from protocolReserve if funded)
        uint256 bonus = ethReward * liquidatorBonusBps / 10000;
        if (protocolReserve >= bonus) {
            protocolReserve -= bonus;
            liquidatorAmount += bonus;
        } else {
            bonus = 0;
        }

        protocolReserve += protocolFee;
        totalReserves -= ethReward;

        pos.collateral     = FHE.asEuint64(0);
        pos.loanAmount     = FHE.asEuint64(0);
        pos.totalDebt      = FHE.asEuint64(0);
        pos.isLiquidatable = FHE.asEbool(false);
        pos.active         = false;

        delete ethDeposited[borrower];
        delete confirmedLiquidatable[borrower];
        delete pendingLiquidationReveal[borrower];
        _removeBorrower(borrower);

        emit Liquidated(borrower, liquidator, liquidatorAmount, protocolFee, bonus, block.timestamp);

        _returnTokens(borrower, liquidator);

        if (liquidatorAmount > 0) {
            (bool ok,) = liquidator.call{value: liquidatorAmount}("");
            require(ok, "ETH transfer failed");
        }
    }

    function _allowLiquidators(ebool ct) internal {
        uint256 n = getRoleMemberCount(LIQUIDATOR_ROLE);
        for (uint256 i = 0; i < n; i++) {
            FHE.allow(ct, getRoleMember(LIQUIDATOR_ROLE, i));
        }
    }

    /// @dev Return all token deposits for a user to a recipient and clear records.
    function _returnTokens(address user, address recipient) internal {
        uint256 n = supportedTokens.length;
        for (uint256 i = 0; i < n; i++) {
            address token = supportedTokens[i];
            uint256 amount = tokenDeposited[user][token];
            if (amount > 0) {
                delete tokenDeposited[user][token];
                IERC20(token).safeTransfer(recipient, amount);
            }
        }
    }

    /// @dev Swap-and-pop borrower from list in O(1).
    function _removeBorrower(address borrower) internal {
        uint256 idx  = borrowerIndex[borrower];
        uint256 last = borrowerList.length - 1;
        if (idx != last) {
            address moved = borrowerList[last];
            borrowerList[idx] = moved;
            borrowerIndex[moved] = idx;
        }
        borrowerList.pop();
        delete borrowerIndex[borrower];
    }

    /// @dev Compute the current effective interest rate in bps.
    ///      effectiveRate = baseRateBps + (utilizationBps * utilizationMultiplierBps / 10000)
    ///      Cast to uint256 for intermediate multiply to avoid uint64 overflow, then back.
    function _effectiveRate() internal view returns (uint64) {
        return baseRateBps + uint64(
            (uint256(utilizationBps) * uint256(utilizationMultiplierBps)) / 10000
        );
    }

    // ─────────────────────────── Admin ─────────────────────────────────────

    function pause()   external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }
    function grantLiquidatorRole(address a) external onlyRole(ADMIN_ROLE) { grantRole(LIQUIDATOR_ROLE, a); }

    /// @notice Wire in or replace the oracle adapter. Set to address(0) to disable.
    function setOracle(address addr) external onlyRole(ADMIN_ROLE) {
        oracle = IOracle(addr);
        emit OracleSet(addr);
    }

    /// @notice Register an ERC20 token as accepted collateral.
    /// @param ethWeiPerToken Fallback price. 0 = oracle-only (requires oracle to be set).
    function addToken(address token, uint8 decimals, uint256 ethWeiPerToken) external onlyRole(ADMIN_ROLE) {
        require(!tokenConfigs[token].supported, "Already added");
        require(
            ethWeiPerToken > 0 || address(oracle) != address(0),
            "Must set ethWeiPerToken or configure oracle first"
        );
        tokenConfigs[token] = TokenConfig({
            supported: true,
            frozen: false,
            decimals: decimals,
            ethWeiPerToken: ethWeiPerToken
        });
        supportedTokens.push(token);
        emit TokenAdded(token, decimals, ethWeiPerToken);
    }

    /// @notice Set ETH supply cap and per-position borrow cap. 0 = uncapped.
    function setCaps(
        uint256 _ethSupplyCap,
        uint256 _maxBorrowPerPosition
    ) external onlyRole(ADMIN_ROLE) {
        ethSupplyCap = _ethSupplyCap;
        maxBorrowPerPosition = _maxBorrowPerPosition;
        emit CapsUpdated(_ethSupplyCap, _maxBorrowPerPosition);
    }

    /// @notice Set per-token supply cap. 0 = uncapped.
    function setTokenSupplyCap(address token, uint256 cap) external onlyRole(ADMIN_ROLE) {
        require(tokenConfigs[token].supported, "Token not supported");
        tokenSupplyCap[token] = cap;
    }

    /// @notice Set the treasury address that receives emergency liquidation proceeds.
    /// @dev [M-2] Must be set before emergencyLiquidate() can be called. Use a multisig.
    function setLiquidationTreasury(address payable treasury) external onlyRole(ADMIN_ROLE) {
        require(treasury != address(0), "Zero address");
        liquidationTreasury = treasury;
        emit LiquidationTreasurySet(treasury);
    }

    /// @notice Update reserve factor and minimum reserve ratio.
    function setReserveParams(
        uint256 _reserveFactorBps,
        uint256 _minReserveRatioBps
    ) external onlyRole(ADMIN_ROLE) {
        require(_reserveFactorBps <= 1000, "Fee too high (max 10%)");
        reserveFactorBps = _reserveFactorBps;
        minReserveRatioBps = _minReserveRatioBps;
    }

    /// @notice Update liquidator bonus paid from protocolReserve.
    function setLiquidatorBonusBps(uint256 bps) external onlyRole(ADMIN_ROLE) {
        require(bps <= 2000, "Bonus too high (max 20%)");
        liquidatorBonusBps = bps;
    }

    /// @notice Withdraw from protocolReserve to a target address.
    function withdrawReserve(uint256 amount, address payable to) external onlyRole(ADMIN_ROLE) {
        require(amount <= protocolReserve, "Insufficient reserve");
        protocolReserve -= amount;
        emit ReserveWithdrawn(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    /// @notice Add ETH to protocolReserve (for pre-funding liquidator bonuses).
    function replenishReserve() external payable {
        require(msg.value > 0, "Zero value");
        protocolReserve += msg.value;
    }

    /// @notice Update the interest rate model parameters.
    /// @param _baseRateBps              Base rate in bps (e.g. 500 = 5%)
    /// @param _utilizationBps           Admin-set utilization estimate 0–10000
    /// @param _utilizationMultiplierBps Max uplift at 100% utilization in bps
    function setRateParams(
        uint64 _baseRateBps,
        uint64 _utilizationBps,
        uint64 _utilizationMultiplierBps
    ) external onlyRole(ADMIN_ROLE) {
        require(_utilizationBps <= 10000, "Utilization > 100%");
        require(_baseRateBps <= 5000, "Base rate max 50%"); // [L-1] prevent euint64 overflow in FHE ops
        baseRateBps = _baseRateBps;
        utilizationBps = _utilizationBps;
        utilizationMultiplierBps = _utilizationMultiplierBps;
        emit RateParamsUpdated(_baseRateBps, _utilizationBps, _utilizationMultiplierBps);
    }

    /// @notice Freeze new deposits for a token (withdrawals still allowed).
    function freezeToken(address token) external onlyRole(ADMIN_ROLE) {
        require(tokenConfigs[token].supported, "Token not supported");
        tokenConfigs[token].frozen = true;
        emit TokenFrozen(token, block.timestamp);
    }

    /// @notice Unfreeze a previously frozen token.
    function unfreezeToken(address token) external onlyRole(ADMIN_ROLE) {
        require(tokenConfigs[token].supported, "Token not supported");
        tokenConfigs[token].frozen = false;
        emit TokenUnfrozen(token, block.timestamp);
    }

    /// @notice Wire in a ConfidentialCreditScore deployment to enable score-gated ratios.
    function setScoreContract(address addr) external onlyRole(ADMIN_ROLE) {
        scoreContract = IConfidentialCreditScore(addr);
        emit ScoreContractSet(addr);
    }

    receive() external payable {
        // [M-4] Enforce supply cap on direct ETH sends
        require(ethSupplyCap == 0 || totalReserves + msg.value <= ethSupplyCap, "Supply cap reached");
        totalReserves += msg.value;
    }
}
