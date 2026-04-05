# ShieldLend — Confidential Overcollateralized Lending

> Built for the **Zama fhEVM Season 2 Hackathon** · Powered by Fully Homomorphic Encryption

[![Zama fhEVM](https://img.shields.io/badge/Built%20with-Zama%20fhEVM-blueviolet)](https://docs.zama.ai)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.27-blue)](https://soliditylang.org)
[![Tests](https://img.shields.io/badge/Tests-57%2F57%20passing-brightgreen)]()
[![Network](https://img.shields.io/badge/Network-Sepolia-orange)]()

**Lending Contract:**
[`0x9013ba38D0b3d4e1587cEFEDebA185f5caee632E`](https://sepolia.etherscan.io/address/0x9013ba38D0b3d4e1587cEFEDebA185f5caee632E)  
**ShieldScore Contract:**
[`0x45D446946FF7186295f7f0413fb5cBfba6ED51C5`](https://sepolia.etherscan.io/address/0x45D446946FF7186295f7f0413fb5cBfba6ED51C5)  
**Frontend:**
[frontend-sigma-seven-16.vercel.app](https://frontend-sigma-seven-16.vercel.app)

---

## The Problem

Every loan on a public blockchain is visible to the world. Competitors can see your collateral ratio, liquidators can front-run your position, and your borrowing history is permanently public. DeFi privacy isn't optional for institutional or high-value borrowers.

ShieldLend solves this using Fully Homomorphic Encryption. Collateral amounts, loan sizes, interest rates, credit scores, and health factors are all computed inside FHE ciphertexts — the protocol enforces overcollateralization and liquidation rules **without ever seeing plaintext values**.

---

## Architecture

ShieldLend is two contracts that work together:

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
├── ConfidentialLending.sol
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
│   └── setScoreContract(addr)       // ADMIN_ROLE — wire in ShieldScore
│
└── shieldscore/
    └── ConfidentialCreditScore.sol  (ShieldScore module)
        ├── Roles: ORACLE_ROLE, REVIEWER_ROLE
        ├── euint64 score per subject  (ACL: subject + oracle)
        ├── setScore / getEncryptedScore / meetsThreshold / hasScore
        └── Dispute system
            ├── openDispute / castDisputeVote (euint8 encrypted votes)
            └── requestDisputeResolve / verifyDisputeResolve
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
| Premium | ≥ 800 | 110% |
| Standard | ≥ 600 | 130% |
| Base | < 600 | 150% |

Score comparisons are done via `FHE.select` — the contract never sees the raw score, only an encrypted boolean result.

---

## Test Results

```
57 passing  (0 failing)

ConfidentialLending (44 tests)
  Deployment, deposit, borrow, repay, interest accrual
  Credit score integration + rate discounts
  Pause/unpause, access control
  Close position (2-step public decryption flow)
  Liquidation (request reveal → verify → execute)
  Borrower list O(1) removal
  ShieldScore tier-gated collateral ratios

ConfidentialCreditScore / ShieldScore (13 tests)
  Oracle: setScore, update, access gating
  Re-encryption: subject decrypts own score
  Threshold: FHE comparison without revealing score
  Dispute: open → vote → resolve
  Dispute constraints: no double-vote, deadline enforcement
  Public decryption: voluntary score reveal
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

### Deploy lending only

```bash
hardhat run scripts/deploy.ts --network sepolia
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

---

## What Makes ShieldLend Different

Most DeFi lending protocols compute collateral ratios in plaintext, making every position visible on-chain. ShieldLend moves all arithmetic — addition, multiplication, division, comparison — inside FHE ciphertexts. The protocol enforces the 150% collateral requirement and liquidation threshold **homomorphically**: the health check produces an encrypted boolean that is only revealed (via the Zama KMS relayer) when needed for liquidation, and even then reveals only a single bit — not the underlying amounts.

ShieldScore extends this further: credit scores are set by an off-chain oracle, stored as `euint64` ciphertexts, and gate both collateral ratios and interest rates without ever being exposed to the protocol. Disputes are resolved by reviewers casting encrypted votes (`euint8`) that are tallied via `FHE.add` — the protocol learns only the outcome, not how each reviewer voted.

---

## License

MIT
