# ShieldLend — Confidential Overcollateralized Lending

> Built for the **Zama fhEVM Season 2 Hackathon** · Powered by Fully Homomorphic Encryption

[![Zama fhEVM](https://img.shields.io/badge/Built%20with-Zama%20fhEVM-blueviolet)](https://docs.zama.ai)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.27-blue)](https://soliditylang.org)
[![Tests](https://img.shields.io/badge/Tests-73%2F73%20passing-brightgreen)]()
[![Network](https://img.shields.io/badge/Network-Sepolia-orange)]()
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-black?logo=vercel)](https://frontend-sigma-seven-16.vercel.app)

**Lending Contract:**
[`0xF9d0f6910f054b4ba36d796475Ae581b7Caad60F`](https://sepolia.etherscan.io/address/0xF9d0f6910f054b4ba36d796475Ae581b7Caad60F)  
**ShieldScore Contract:**
[`0x084900bdf01193b158989518Bc6242B1C201273F`](https://sepolia.etherscan.io/address/0x084900bdf01193b158989518Bc6242B1C201273F)  
**Frontend:**
[frontend-sigma-seven-16.vercel.app](https://frontend-sigma-seven-16.vercel.app)

---

## Why This Matters

DeFi lending today has a fundamental privacy problem. When Alice deposits 100 ETH on Aave, **everyone** can see:
- Her exact collateral balance
- How much she borrowed
- Her health factor (and exactly when she can be liquidated)
- Her complete borrowing history

This creates real damage:

- **Competitors** track institutional borrowing positions to front-run trades
- **MEV bots** snipe liquidations by watching health factors approach thresholds
- **Credit history** is permanently public — a single bad position follows you forever

For DeFi to serve institutional and high-net-worth users, lending needs to work like traditional finance: **the protocol enforces the rules without seeing the data.**

### How ShieldLend Solves This

ShieldLend moves *all* lending arithmetic inside FHE ciphertexts. The protocol computes collateral ratios, interest accrual, and liquidation thresholds homomorphically — it enforces overcollateralization **without ever knowing the amounts involved.**

**Scenario: Alice borrows privately**

1. Alice deposits 10 ETH. The amount is encrypted client-side via the Zama relayer SDK before reaching the chain — the contract stores it as an `euint64` ciphertext.
2. Alice borrows against her collateral. The contract computes `collateral * 100 < debt * 150` entirely in FHE to check the health factor — producing an encrypted boolean `ebool`.
3. The protocol accrues interest via `FHE.mul` and `FHE.add` on encrypted values. Alice's rate is personalized by her encrypted ShieldScore credit rating — without the protocol seeing the score.
4. If Alice's health factor deteriorates, anyone can request a **single-bit reveal**: the `ebool isLiquidatable` is publicly decrypted via the Zama KMS relayer. The world learns only *whether* she's underwater — not her collateral ratio, debt, or score.

**What the blockchain sees:** encrypted blobs. **What the protocol enforces:** 150% overcollateralization, 66% max LTV, interest accrual, liquidation thresholds — all verified homomorphically.

---

## ★ What Makes ShieldScore Novel

Most FHE lending demos stop at encrypting balances. ShieldLend goes further with a **two-contract system where the credit score permanently shapes the protocol's behaviour — without the protocol ever seeing the score.**

### The key insight: encrypted policy, not encrypted data

Every existing credit scoring system in DeFi (Spectral, ARCx, Masa) computes a score **in the clear** and stores it publicly. The "privacy" is just UI — the raw data is on-chain.

ShieldScore inverts this:

```
Traditional DeFi credit:         ShieldScore architecture:
─────────────────────────         ────────────────────────
score = public uint256            score = euint64 ciphertext
protocol reads score              protocol NEVER reads score
computes ratio in clear           FHE.select picks ratio blindly
anyone can see your tier          only YOU can decrypt your score
```

The lending contract calls `FHE.select(meetsThreshold, tightRatio, looseRatio)` — it gets the right collateral ratio back **without learning which branch was taken.** This is a fundamentally different privacy model from anything deployed on Ethereum today.

### Encrypted dispute voting

When a borrower believes their score is wrong, they open a dispute. Reviewers cast `euint8` encrypted votes. The contract tallies them via `FHE.add` — the final count is publicly revealed, but **individual votes are never exposed.** This gives verifiable vote integrity with ballot secrecy, using only FHE primitives.

### Composability: any protocol can plug in ShieldScore

`ConfidentialCreditScore` is fully decoupled. Any fhEVM lending, insurance, or yield protocol can call `meetsThreshold()` or `getEncryptedScore()` and gate their own logic on a user's credit tier — without reading the score. It's a **private credit primitive for DeFi.**

---



ShieldLend is two composable contracts:

```
ConfidentialLending.sol       — core lending protocol (deposit, borrow, repay, liquidate)
ConfidentialCreditScore.sol   — ShieldScore: encrypted credit scoring + dispute system
```

`ConfidentialLending` optionally wires in `ConfidentialCreditScore` via `setScoreContract()`. When wired, a borrower's encrypted credit score gates their collateral ratio and interest rate — without revealing the score to the protocol.

---

## How It Works

### Encrypted Lending Math

All core protocol logic runs on encrypted values:

```solidity
// Borrow: health factor computed entirely in FHE
euint64 collateralScaled = FHE.mul(pos.collateral, FHE.asEuint64(100));
euint64 debtScaled       = FHE.mul(pos.totalDebt,  FHE.asEuint64(150)); // 150% ratio
pos.isLiquidatable       = FHE.lt(collateralScaled, debtScaled);

// Interest accrual: totalDebt * interestRate / 10000 — all encrypted
euint64 interest = FHE.div(FHE.mul(pos.totalDebt, pos.interestRate), 10000);
pos.totalDebt    = FHE.add(pos.totalDebt, interest);

// Credit score → interest rate discount: all encrypted
euint64 discount = FHE.div(FHE.div(newScore, 2), 100);
pos.interestRate = FHE.sub(FHE.asEuint64(BASE_RATE_BPS), discount);
```

No plaintext amount, rate, or health factor is ever stored or computed in the clear.

### Encryption Flow (Client → Chain)

```
Browser (relayer-sdk)
  └─ encryptUint(depositAmount, contractAddress, userAddress)
       → externalEuint64 handle + ZK inputProof
            │
            ▼
  ConfidentialLending.sol
  └─ FHE.fromExternal(handle, inputProof)  // verify proof + store as euint64
  └─ FHE.allowThis(euint64)               // contract retains ACL access
  └─ FHE.allow(euint64, msg.sender)       // borrower can re-encrypt to view
```

### Public Decryption — Liquidation Reveal

The liquidation health check (`isLiquidatable`) is an FHE-computed `ebool`. Anyone can request it be publicly revealed without exposing the underlying collateral or debt:

```
1. requestLiquidationReveal(borrower)
   └─ FHE.makePubliclyDecryptable(pos.isLiquidatable)

2. Zama KMS relayer decrypts the ebool off-chain

3. verifyLiquidationReveal(borrower, handles, cleartexts, proof)
   └─ FHE.checkSignatures(handles, cleartexts, proof)
   └─ confirmedLiquidatable[borrower] = bool
```

**The health factor stays encrypted.** The world only learns whether a position crossed the liquidation threshold — not the exact collateral ratio.

---

## Contract Architecture

```
contracts/
├── ConfidentialLending.sol (745 lines)
│   ├── Roles: ADMIN_ROLE, LIQUIDATOR_ROLE
│   ├── Position (all encrypted per borrower)
│   │   ├── euint64 collateral
│   │   ├── euint64 loanAmount
│   │   ├── euint64 totalDebt
│   │   ├── euint64 interestRate     // gated by credit score
│   │   ├── euint64 creditScore
│   │   └── ebool   isLiquidatable
│   ├── deposit / borrow / repay / accrueInterest
│   ├── requestLiquidationReveal / verifyLiquidationReveal / liquidate
│   ├── requestClosePosition / verifyAndClose
│   ├── Admin: oracle, rate model, caps, reserve, emergency liquidation
│   └── setScoreContract(addr)       // ADMIN_ROLE — wire in ShieldScore
│
└── shieldscore/
    └── ConfidentialCreditScore.sol (295 lines) — ShieldScore module
        ├── Roles: ORACLE_ROLE, REVIEWER_ROLE
        ├── euint64 score per subject  (ACL: subject + oracle)
        ├── setScore / getEncryptedScore / meetsThreshold / hasScore
        └── Dispute system
            ├── openDispute / castDisputeVote (euint8 encrypted votes)
            └── requestDisputeResolve / verifyDisputeResolve
```

### Frontend Architecture

```
frontend/src/
├── App.tsx                      — thin orchestrator, state management
├── components/
│   ├── Header.tsx               — wallet connection, FHE status, role badge
│   ├── Hero.tsx                 — landing page with feature cards
│   ├── StatsBar.tsx             — protocol stats overview
│   ├── BorrowerCard.tsx         — position management (deposit/borrow/repay/decrypt)
│   ├── LiquidatorCard.tsx       — borrower monitoring + liquidation flow
│   ├── AdminPanel.tsx           — reserve, rate model, caps, emergency controls
│   ├── Modals.tsx               — deposit, borrow/repay, score, result modals
│   └── Toast.tsx                — notification system
├── ShieldScore.tsx              — standalone credit score panel
├── styles.ts                    — design system (Space Mono + Syne typography)
├── types.ts                     — shared TypeScript types
└── config.ts                    — contract addresses, token config
```

---

## Protocol Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `COLLATERAL_RATIO` | 150% | Default overcollateralization |
| `MIN_HEALTH_FACTOR` | 110% | Liquidation threshold |
| `BASE_RATE_BPS` | 500 | 5% base annual interest |
| `MAX_LOAN_RATIO` | 66% | Max borrow against collateral |

### Credit Score Tiers (ShieldScore)

| Tier | Score | Collateral Ratio |
|------|-------|-----------------|
| Premium | >= 800 | 110% |
| Standard | >= 600 | 130% |
| Base | < 600 | 150% |

Score comparisons are done via `FHE.select` — the contract never sees the raw score, only an encrypted boolean result.

---

## Interest Accrual & the Keeper Bot

Because summing all encrypted position debts on-chain would break FHE privacy, interest accrual is triggered externally. ShieldLend includes a **keeper script** (`scripts/keeper.ts`) that:

1. Iterates over all active borrowers via `borrowerList`
2. Calls `accrueInterest(borrower)` for each position
3. Logs results with transaction hashes

In production, this runs as a cron job or systemd timer:

```bash
# Accrue interest every 6 hours
0 */6 * * * cd /path/to/shieldlend && \
  PRIVATE_KEY=0x... npx hardhat run scripts/keeper.ts --network sepolia
```

This is an intentional design choice: automated on-chain utilization tracking would require aggregating encrypted debt values, which fundamentally contradicts FHE privacy guarantees. The keeper approach preserves per-position confidentiality while maintaining protocol health.

---

## Credit Score Oracle — Production Path

ShieldScore's `ORACLE_ROLE` currently sets scores via admin. In production, this would connect to a privacy-preserving credit scoring pipeline:

```
                                        ┌─────────────────────┐
                                        │  ShieldScore Oracle  │
                                        │  (off-chain service) │
                                        └────────┬────────────┘
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    │                            │                            │
         ┌──────────▼──────────┐    ┌────────────▼──────────┐    ┌───────────▼──────────┐
         │  On-Chain History   │    │  Cross-Protocol Data  │    │  Off-Chain Signals    │
         │  - Repayment record │    │  - Aave/Compound      │    │  - KYC provider       │
         │  - Liquidation count│    │  - Uniswap LP history │    │  - Credit bureau API  │
         │  - Position age     │    │  - ENS/governance     │    │  - Employer oracle    │
         └─────────────────────┘    └───────────────────────┘    └──────────────────────┘
                                                 │
                                    ┌────────────▼────────────┐
                                    │  Score Computation      │
                                    │  (0–1000, off-chain)    │
                                    │  weighted model output  │
                                    └────────────┬────────────┘
                                                 │
                                    ┌────────────▼────────────┐
                                    │  Encrypt & Submit       │
                                    │  fhevmjs.encryptUint()  │
                                    │  → setScore(subject,    │
                                    │     handle, proof)      │
                                    └─────────────────────────┘
```

The oracle encrypts the score client-side before submission — **even the oracle contract never stores a plaintext score.** The lending protocol only sees `meetsThreshold()` results as encrypted booleans, preserving creditworthiness privacy end-to-end.

Future enhancements could use **zkTLS** or **TEE attestations** to prove the off-chain data sources without revealing them, creating a fully verifiable yet private credit scoring pipeline.

---

## Test Results

```
73 passing  (0 failing)

ConfidentialLending (37 tests)
  Deployment, deposit, borrow, repay, interest accrual
  Credit score integration + rate discounts
  Pause/unpause, access control
  Close position (2-step public decryption flow)
  Liquidation (request reveal → verify → execute)
  Borrower list O(1) removal
  ShieldScore tier-gated collateral ratios
  Core FHE math: userDecryptEbool health factor, publicDecryptEbool liquidation reveal

ConfidentialLending — Adversarial (16 tests)
  Near-threshold: exactly 150% is NOT liquidatable; 1 wei below IS
  Overflow-boundary: large values do not silent-wrap
  Floor-at-zero: repay ≥ debt → totalDebt = 0, not underflow
  Sequential accrual: debt grows monotonically
  Borrow caps: one-wei-over reverts
  Reserve gate: borrow reverts below minReserveRatio

ConfidentialCreditScore / ShieldScore (20 tests)
  Oracle: setScore, update, access gating
  userDecrypt: subject decrypts own encrypted score
  meetsThreshold: FHE comparison without revealing score
  Dispute: open → cast encrypted vote → resolve via public decryption
  Dispute constraints: no double-vote, deadline enforcement, vote tally
  Public decryption: voluntary score reveal flow
```

---

## Local Setup

```bash
git clone https://github.com/Laolex/shieldlend
cd shieldlend
npm install
npx hardhat test
```

### Frontend

```bash
cd frontend
cp .env.example .env       # fill in VITE_SCORE_CONTRACT_ADDRESS after deploying
npm install
npm run dev                # http://localhost:5173
```

---

## Deployment

### Deploy all contracts (lending + ShieldScore, wired together)

```bash
npm run deploy-all:sepolia
```

This deploys `ConfidentialCreditScore`, deploys `ConfidentialLending`, calls `setScoreContract`, and prints both addresses.

After deployment:
1. Update `frontend/src/config.ts` with the new `CONTRACT_ADDRESS`
2. Set `VITE_SCORE_CONTRACT_ADDRESS` in `frontend/.env`
3. Push to Vercel — env vars can also be set in Vercel dashboard

### Run the keeper

```bash
PRIVATE_KEY=0x... npx hardhat run scripts/keeper.ts --network sepolia
```

### Etherscan Verification (Standard JSON Input)

```bash
node -e "
const fs = require('fs');
const f = fs.readdirSync('artifacts/build-info').find(f => f.endsWith('.json'));
const bi = JSON.parse(fs.readFileSync('artifacts/build-info/' + f));
fs.writeFileSync('std_input.json', JSON.stringify(bi.input, null, 2));
"
```

Upload `std_input.json` → Etherscan → Verify & Publish → Solidity (Standard-Json-Input).

---

## Stack

| Layer | Technology |
|-------|------------|
| FHE Contract Library | `@fhevm/solidity` v0.11.1 |
| FHE Client SDK | `@zama-fhe/relayer-sdk` v0.4.1 |
| Smart Contracts | Solidity 0.8.27 + OpenZeppelin |
| Network | Ethereum Sepolia |
| Frontend | React 19 + Vite + ethers.js v6 |
| Deploy | Vercel (frontend + API edge functions) |
| Testing | Hardhat + fhEVM mock coprocessor |
| Keeper | Hardhat script + cron |

---

## FHE Patterns Used

ShieldLend demonstrates 8 distinct FHE patterns from the Zama fhEVM toolkit:

| Pattern | Where Used |
|---------|-----------|
| `FHE.fromExternal` + `inputProof` | Every user input (deposit, borrow, repay, score) |
| `FHE.add` / `FHE.sub` / `FHE.mul` / `FHE.div` | Interest accrual, collateral aggregation, rate computation |
| `FHE.lt` (encrypted comparison) | Health factor check → `ebool isLiquidatable` |
| `FHE.select` (encrypted branching) | Credit score tier → collateral ratio selection |
| `FHE.allow` / `FHE.allowThis` (ACL) | Per-user ciphertext access control |
| `FHE.makePubliclyDecryptable` | Liquidation reveal, debt-zero check, dispute resolution |
| `FHE.checkSignatures` | Verifying Zama KMS relayer decryption proofs |
| `euint8` encrypted voting | Dispute system — tallied via `FHE.add`, never revealing individual votes |

---

## License

MIT
