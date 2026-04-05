# ShieldLend Protocol Upgrades — Design Spec
Date: 2026-04-05
Status: Approved

## Overview

Upgrade ShieldLend to close the top 9 protocol gaps identified by gap analysis against Aave V3 / Compound V3 and the FHEVM skill. Flash loans (gap #8) are explicitly out of scope.

All Solidity changes require redeployment (no upgradeable proxy). New contract addresses must be propagated to frontend `.env` and Vercel env vars after deployment.

---

## Scope

| Gap | Feature | Priority |
|-----|---------|----------|
| 1 | Chainlink oracle adapter | CRITICAL |
| 2 | Supply / borrow caps | CRITICAL |
| 3 | Bad debt absorption (lite) via protocolReserve | CRITICAL |
| 4 | Adversarial FHE test suite | CRITICAL |
| 5 | Liquidation bonus + protocol fee | HIGH |
| 6 | Admin-configurable interest rate model | HIGH |
| 7 | Emergency admin functions | HIGH |
| 8 | Flash loans | OUT OF SCOPE |
| 9 | Reserve factor (from liquidation proceeds) | MEDIUM |
| 10 | Permissionless liquidation post-confirm | MEDIUM |

---

## Architecture

### New file: `contracts/ChainlinkOracle.sol`
Standalone oracle adapter. No FHE imports. Deployed separately before `ConfidentialLending`.

### Modified file: `contracts/ConfidentialLending.sol`
All protocol logic stays in one file. `ChainlinkOracle` is wired in via `IOracle` interface.

### Unchanged: `contracts/shieldscore/ConfidentialCreditScore.sol`
No changes needed.

### New test file: `test/ConfidentialLending.adversarial.test.ts`
Adversarial edge-case coverage for FHE math correctness.

### Modified: `scripts/deploy-all.ts`
Deploy oracle first, then lending contract, wire together.

---

## Section 1: `IOracle.sol` + `ChainlinkOracle.sol`

### Interface

```solidity
interface IOracle {
    function getEthWeiPerToken(address token) external view returns (uint256);
    function isStale(address token) external view returns (bool);
}
```

### `ChainlinkOracle` contract

**State:**
- `mapping(address => address) public aggregators` — token → Chainlink AggregatorV3Interface
- `mapping(address => bool) public isUsdFeed` — if true, price is token/USD and needs ETH/USD conversion
- `address public ethUsdAggregator` — ETH/USD feed (Sepolia: `0x694AA1769357215DE4FAC081bf1f309aDC325306`)
- `mapping(address => uint256) public fallbackPrices` — admin override for tokens without Chainlink feed
- `uint256 public maxStaleness = 3600` — seconds; staleness threshold

**Admin functions (Ownable):**
- `addFeed(address token, address aggregator, bool _isUsdFeed)` — register a Chainlink feed
- `setFallbackPrice(address token, uint256 ethWeiPerToken)` — admin override
- `setMaxStaleness(uint256 seconds)` — update staleness threshold

**View functions:**
- `getEthWeiPerToken(address token) → uint256`
  - If token has a Chainlink aggregator: fetch `latestRoundData()`, check staleness, convert to ETH-wei
  - If `isUsdFeed[token]`: divide token USD price by ETH/USD price to get ETH-denominated price, then scale to 18 decimals
  - If no aggregator: use `fallbackPrices[token]`, revert if also zero
  - Reverts if price ≤ 0 or stale
- `isStale(address token) → bool`
  - Returns true if `block.timestamp - updatedAt > maxStaleness`

**Price conversion (USD feed):**
```
ethWeiPerToken = (tokenUsdPrice * 1e18) / ethUsdPrice
```
Where both prices come from Chainlink with their respective decimals (typically 8).

**Sepolia Chainlink feeds:**
- ETH/USD: `0x694AA1769357215DE4FAC081bf1f309aDC325306`
- Other test tokens: use `setFallbackPrice()` since Sepolia feeds are limited

---

## Section 2: `ConfidentialLending.sol` Changes

### 2.1 Oracle Integration

**New state:**
```solidity
IOracle public oracle;  // address(0) = use TokenConfig.ethWeiPerToken fallback
```

**New admin function:**
```solidity
function setOracle(address addr) external onlyRole(ADMIN_ROLE)
```

**`depositToken()` changes:**
- If `oracle != address(0)`: call `oracle.getEthWeiPerToken(token)` — reverts if stale
- Emit `TokenPriceUsed(token, price, block.timestamp)` so frontend can read the authoritative price for computing encrypted ETH equivalent
- `TokenConfig.ethWeiPerToken` becomes the fallback when oracle is not set

**`addToken()` changes:**
- `ethWeiPerToken` param becomes optional (0 = oracle-only token). Reverts if both oracle is address(0) and ethWeiPerToken is 0.

**Design note documented in NatDoc:**
> The oracle cannot validate the encrypted input amount — the client computes the ETH-wei equivalent off-chain using the oracle price and submits it encrypted. The oracle enforces price freshness at deposit time; clients must read the `TokenPriceUsed` event or call `oracle.getEthWeiPerToken()` before encrypting their deposit amount.

### 2.2 Supply / Borrow Caps

**New state:**
```solidity
uint256 public ethSupplyCap;                       // max totalReserves (0 = uncapped)
mapping(address => uint256) public tokenSupplyCap; // max units of each token (0 = uncapped)
uint256 public maxBorrowPerPosition;               // per-position ETH cap (0 = uncapped)
```

**New admin function:**
```solidity
function setCaps(
    uint256 _ethSupplyCap,
    uint256 _maxBorrowPerPosition
) external onlyRole(ADMIN_ROLE)

function setTokenSupplyCap(address token, uint256 cap) external onlyRole(ADMIN_ROLE)
```

**Enforcement:**
- `deposit()`: `require(ethSupplyCap == 0 || totalReserves + msg.value <= ethSupplyCap)`
- `depositToken()`: `require(tokenSupplyCap[token] == 0 || tokenDeposited[msg.sender][token] + tokenAmount <= tokenSupplyCap[token])`
- `borrow()`: `require(maxBorrowPerPosition == 0 || ethDeposited[msg.sender] <= maxBorrowPerPosition)`
  - Note: this caps collateral size, making the effective borrow cap `MAX_LOAN_RATIO (66%) * maxBorrowPerPosition`. E.g. cap of 10 ETH → max borrow ≈ 6.6 ETH.

**FHE limitation note:**
> Total borrowed across all positions cannot be tracked in plaintext because borrow amounts are encrypted. `maxBorrowPerPosition` is a per-user plaintext cap enforced via collateral size (max borrow = 66% of cap). A global borrow cap would require FHE aggregation of all encrypted debts — a research-frontier operation outside this protocol's scope.

### 2.3 Reserve Factor + Bad Debt Absorption

**New state:**
```solidity
uint256 public protocolReserve;       // accumulated protocol fees in ETH-wei
uint256 public reserveFactorBps;      // default: 200 (2%)
uint256 public minReserveRatioBps;    // default: 500 (5% of totalReserves)
```

**Reserve accumulation** — taken from liquidation proceeds (avoids FHE arithmetic on encrypted interest):
- In `liquidate()`: `protocolFee = ethReward * reserveFactorBps / 10000`
- `protocolReserve += protocolFee`
- Liquidator receives `ethReward - protocolFee` (plus bonus from existing reserve — see Section 2.4)

**Net reserve math per liquidation:**
- Reserve gains: `+reserveFactorBps` (2%) of collateral
- Reserve loses: `+liquidatorBonusBps` (5%) of collateral (if reserve has funds)
- Net: `-300 bps` per liquidation when bonus is paid
- Implication: protocol reserve must be pre-funded via `replenishReserve()` before the first liquidation, or `liquidatorBonusBps` set ≤ `reserveFactorBps` until reserve is established

**Bad debt gate:**
- In `borrow()`: `require(minReserveRatioBps == 0 || protocolReserve >= totalReserves * minReserveRatioBps / 10000, "Reserve too low")`
- If reserve falls below minimum (e.g., after absorbing bad debt losses), new borrows halt
- Admin replenishes reserve via direct ETH transfer to contract (`receive()` already adds to `totalReserves` — add a separate `replenishReserve()` payable function that adds to `protocolReserve`)

**Admin functions:**
```solidity
function setReserveParams(uint256 _reserveFactorBps, uint256 _minReserveRatioBps) external onlyRole(ADMIN_ROLE)
function withdrawReserve(uint256 amount, address payable to) external onlyRole(ADMIN_ROLE)
function replenishReserve() external payable  // adds msg.value to protocolReserve only
```

### 2.4 Liquidation Bonus

**New state:**
```solidity
uint256 public liquidatorBonusBps;  // default: 500 (5%) — funded from protocol reserve
```

**Updated `liquidate()` logic:**
```solidity
uint256 ethReward = ethDeposited[borrower];
uint256 protocolFee = ethReward * reserveFactorBps / 10000;
uint256 liquidatorAmount = ethReward - protocolFee;

// Bonus from protocol reserve (if available)
uint256 bonus = ethReward * liquidatorBonusBps / 10000;
if (protocolReserve >= bonus) {
    protocolReserve -= bonus;
    liquidatorAmount += bonus;
}

protocolReserve += protocolFee;
totalReserves -= ethReward;
```

**Updated `Liquidated` event:**
```solidity
event Liquidated(
    address indexed borrower,
    address indexed liquidator,
    uint256 ethTransferred,
    uint256 protocolFee,
    uint256 bonus,
    uint256 timestamp
);
```

### 2.5 Permissionless Liquidation

**Change:** Remove `onlyRole(LIQUIDATOR_ROLE)` from `liquidate()`.

Any address can liquidate once `confirmedLiquidatable[borrower]` is set after the 3-step reveal. This removes the centralized bottleneck.

**New function:** `emergencyLiquidate(address borrower)` — ADMIN_ROLE only, skips `confirmedLiquidatable` check. For stuck positions or oracle-failure recovery.

```solidity
function emergencyLiquidate(address borrower)
    external onlyRole(ADMIN_ROLE) nonReentrant
```

Same logic as `liquidate()` minus the `confirmedLiquidatable` check.

### 2.6 Interest Rate Model

**Remove:** `uint64 public constant BASE_RATE_BPS = 500`

**New state:**
```solidity
uint64 public baseRateBps;              // default: 500 (5%)
uint64 public utilizationBps;           // admin-set estimate: 0–10000
uint64 public utilizationMultiplierBps; // default: 1000 (10% max uplift at 100% utilization)
```

**Effective rate:**
```solidity
// Cast to uint256 for intermediate multiplication to avoid uint64 overflow,
// then cast back (result fits uint64: max = 10000 * 10000 / 10000 = 10000)
uint64 effectiveRate = baseRateBps + uint64(
    (uint256(utilizationBps) * uint256(utilizationMultiplierBps)) / 10000
);
```

Applied in `_applyCollateral()` (initial rate for new positions) and when `updateCreditScore()` recomputes the per-user rate (credit discount applied on top of `effectiveRate`).

**New admin function:**
```solidity
function setRateParams(
    uint64 _baseRateBps,
    uint64 _utilizationBps,
    uint64 _utilizationMultiplierBps
) external onlyRole(ADMIN_ROLE)
```

**NatDoc:**
> Automated utilization tracking requires summing all encrypted position debts, which breaks FHE privacy. Admin monitors utilization off-chain and calls setRateParams() to adjust. A production deployment would use either a privacy-preserving aggregation scheme or accept limited privacy on total-borrow for rate accuracy.

### 2.7 Emergency Admin Functions

```solidity
// Freeze/unfreeze token deposits
function freezeToken(address token) external onlyRole(ADMIN_ROLE)
function unfreezeToken(address token) external onlyRole(ADMIN_ROLE)

// TokenConfig gains: bool frozen
// depositToken() checks: require(!tokenConfigs[token].frozen, "Token frozen")

// Already covered above:
function emergencyLiquidate(address borrower) external onlyRole(ADMIN_ROLE) nonReentrant
function setOracle(address addr) external onlyRole(ADMIN_ROLE)
function setRateParams(...) external onlyRole(ADMIN_ROLE)
function setCaps(...) external onlyRole(ADMIN_ROLE)
function setReserveParams(...) external onlyRole(ADMIN_ROLE)
function withdrawReserve(...) external onlyRole(ADMIN_ROLE)
```

**New events:**
```solidity
event TokenFrozen(address indexed token, uint256 timestamp);
event TokenUnfrozen(address indexed token, uint256 timestamp);
event OracleSet(address indexed oracle);
event RateParamsUpdated(uint64 baseRate, uint64 utilization, uint64 multiplier);
event CapsUpdated(uint256 ethSupplyCap, uint256 maxBorrowPerPosition);
event ReserveWithdrawn(address indexed to, uint256 amount);
event EmergencyLiquidation(address indexed borrower, address indexed admin, uint256 timestamp);
```

---

## Section 3: Adversarial Test Suite

**File:** `test/ConfidentialLending.adversarial.test.ts`

Ten test cases targeting FHE math correctness and protocol invariants:

| # | Name | What it proves |
|---|------|----------------|
| 1 | near-threshold | Position at exactly 150% ratio; single wei change flips `isLiquidatable` |
| 2 | overflow-boundary | Collateral + debt approaching `uint64.max`; no silent wrap |
| 3 | floor-at-zero exact | Repay == debt → totalDebt = 0, not underflow |
| 4 | floor-at-zero excess | Repay > debt → totalDebt = 0, not underflow |
| 5 | multi-collateral health | ETH + token combined collateral; correct health factor |
| 6 | sequential-accrual | 5 interest accruals; totalDebt grows monotonically, health degrades correctly |
| 7 | credit-score-tiers | Score < 600 → 150%, 600–799 → 130%, ≥ 800 → 110% ratio used |
| 8 | borrow-at-cap | Borrow exactly at `maxBorrowPerPosition`; one-wei-over reverts |
| 9 | reserve-gate | Drain `protocolReserve` below `minReserveRatioBps`; borrow reverts |
| 10 | permissionless-liquidate | Non-LIQUIDATOR_ROLE address liquidates after confirm; receives bonus |

---

## Section 4: Deploy Script + Frontend

### `scripts/deploy-all.ts` changes

Deployment order:
1. Deploy `ChainlinkOracle`
2. Call `oracle.addFeed(WETH_ADDRESS, ETH_USD_AGGREGATOR, true)`
3. For test tokens: `oracle.setFallbackPrice(token, price)`
4. Deploy `ConfidentialLending`
5. Call `lending.setOracle(oracle.address)`
6. Call `lending.setCaps(100 ether, 10 ether)`
7. Call `lending.setRateParams(500, 0, 1000)` — start at 0% utilization
8. Call `lending.setReserveParams(200, 500)` — 2% fee, 5% min ratio
9. Deploy `ConfidentialCreditScore` (unchanged)
10. Call `lending.setScoreContract(score.address)`
11. Print all addresses + update `.env.example`

### Frontend changes

**`src/config.ts`:**
- Add `ORACLE_ADDRESS` from env

**`src/App.tsx`:**
- Before calling `depositToken()`: read oracle price via `oracle.getEthWeiPerToken(token)` view call or `TokenPriceUsed` event — use this price for the encrypted ETH-wei equivalent computation
- Display `protocolReserve` and `utilizationBps` in the protocol stats panel

**`.env.example`:**
```
VITE_LENDING_ADDRESS=<new address>
VITE_SCORE_ADDRESS=<new address>
VITE_ORACLE_ADDRESS=<new address>
```

---

## Deployment Notes

- All contract changes require new Sepolia deployments
- New addresses must be set in Vercel project env vars after deploy
- `ConfidentialCreditScore` can be redeployed or reused (no changes) — reuse if existing deploy still works
- Run `npx hardhat test` (all 57 existing + new adversarial tests) before deploying
- Verify contracts on Etherscan using existing `std_input.json` pattern

---

## Out of Scope

- Flash loans (low hackathon value, 3-5 days implementation risk)
- Formal verification / fuzzing beyond the adversarial test suite
- DAO governance / timelocks
- Partial liquidations (requires revealing debt amount — 4-step flow)
- Permissionless liquidation without oracle (needs oracle to prevent griefing)
- Automated utilization tracking (requires FHE aggregation of encrypted debts)
