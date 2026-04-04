# ShieldLend — Confidential Overcollateralized Lending

> Built for the **Zama fhEVM Season 2 Hackathon** · Powered by Fully Homomorphic Encryption

[![Zama fhEVM](https://img.shields.io/badge/Built%20with-Zama%20fhEVM-blueviolet)](https://docs.zama.ai)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue)](https://soliditylang.org)
[![Tests](https://img.shields.io/badge/Tests-22%2F22%20passing-brightgreen)]()
[![Network](https://img.shields.io/badge/Network-Sepolia-orange)]()

**Contract:**
[`0xFC0f1744d3cF752Bdd67c0BA4b0CaD4048f7376A`](https://sepolia.etherscan.io/address/0xFC0f1744d3cF752Bdd67c0BA4b0CaD4048f7376A)  
**Frontend:**
[frontend-sigma-seven-16.vercel.app](https://frontend-sigma-seven-16.vercel.app)

---

## The Problem

Every loan on a public blockchain is visible to the world. Competitors can see your collateral ratio, liquidators can front-run your position, and your borrowing history is permanently public. DeFi privacy isn't optional for institutional or high-value borrowers.

ShieldLend solves this using Fully Homomorphic Encryption. Collateral amounts, loan sizes, interest rates, credit scores, and health factors are all computed inside FHE ciphertexts — the protocol enforces overcollateralization and liquidation rules **without ever seeing plaintext values**.

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
euint64 discount     = FHE.div(FHE.div(newScore, 2), 100);
pos.interestRate     = FHE.sub(FHE.asEuint64(BASE_RATE_BPS), discount);
```

No plaintext amount, rate, or health factor is ever stored or computed in the clear.

### Encryption Flow (Client → Chain)

```
Browser (fhevmjs)
  └─ encryptUint(depositAmount, contractAddress, userAddress)
       → externalEuint64 handle + ZK inputProof
            │
            ▼
  ConfidentialLending.sol
  └─ FHE.fromExternal(handle, inputProof)  // verify proof + store as euint64
  └─ FHE.allowThis(euint64)               // contract retains ACL access
  └─ FHE.allow(euint64, msg.sender)       // borrower can re-encrypt/view
```

### Public Decryption — Liquidation Reveal

The liquidation health check (`isLiquidatable`) is an FHE-computed `ebool`. Anyone can request it be publicly revealed without exposing the underlying collateral or debt values:

```
1. requestLiquidationReveal(borrower)
   └─ FHE.makePubliclyDecryptable(pos.isLiquidatable)
   └─ emit LiquidationRevealRequested(borrower, handle)

2. Zama relayer decrypts the ebool off-chain

3. verifyLiquidationReveal(borrower, handles, cleartexts, proof)
   └─ FHE.checkSignatures(handles, cleartexts, proof)  // verify KMS signatures
   └─ bool isLiq = abi.decode(cleartexts, (bool))
   └─ emit LiquidationAlertPublic(borrower, isLiq)
```

**The health factor stays encrypted.** The world only learns whether a position crossed the liquidation threshold — not the exact collateral ratio.

---

## Contract Architecture

```
ConfidentialLending.sol
├── ZamaEthereumConfig          // Zama FHE coprocessor addresses
├── AccessControlEnumerable     // ADMIN_ROLE, LIQUIDATOR_ROLE
├── ReentrancyGuard
├── Pausable
│
├── Position (per borrower, all encrypted)
│   ├── euint64 collateral       // deposited ETH in wei
│   ├── euint64 loanAmount       // principal borrowed
│   ├── euint64 interestRate     // per-user rate in bps (credit-score gated)
│   ├── euint64 totalDebt        // principal + accrued interest
│   ├── euint64 creditScore      // 0–1000 encrypted score
│   └── ebool   isLiquidatable   // FHE.lt(collateral*100, debt*150)
│
├── Core Functions
│   ├── deposit()                // encrypt collateral + init position
│   ├── borrow()                 // add debt + recompute health factor
│   ├── repay()                  // reduce debt + recompute health factor
│   ├── accrueInterest()         // encrypted per-user compound interest
│   ├── liquidate()              // LIQUIDATOR_ROLE only
│   └── updateCreditScore()      // ADMIN_ROLE — sets encrypted score + rate
│
└── Public Decryption
    ├── requestLiquidationReveal()    // makePubliclyDecryptable + emit handle
    ├── verifyLiquidationReveal()     // checkSignatures + emit plaintext result
    └── isPendingReveal()             // view — check reveal status
```

---

## Protocol Constants (Plaintext)

| Constant | Value | Meaning |
|----------|-------|---------|
| `COLLATERAL_RATIO` | 150 | 150% overcollateralization required |
| `MIN_HEALTH_FACTOR` | 110 | Liquidation threshold |
| `BASE_RATE_BPS` | 500 | 5% base annual interest rate |
| `MAX_LOAN_RATIO` | 66 | Max 66% of collateral can be borrowed |

Protocol rules are public; position sizes are private.

---

## Test Results

```
22 passing  (0 failing)

Deposit:
  ✓ initializes position with encrypted collateral and default credit score
  ✓ adds to existing collateral on second deposit

Borrow:
  ✓ increases encrypted totalDebt
  ✓ sets isLiquidatable based on FHE.lt health factor check

Repay:
  ✓ reduces totalDebt and loanAmount via FHE.sub

Interest accrual:
  ✓ increases totalDebt by encrypted interest calculation

Liquidate:
  ✓ only LIQUIDATOR_ROLE can liquidate
  ✓ zeroes position and sets active = false

Credit score:
  ✓ ADMIN_ROLE sets encrypted credit score
  ✓ lower interest rate computed from higher score via FHE.div

Access control:
  ✓ non-admin cannot update credit score
  ✓ non-liquidator cannot liquidate

Public Decryption — Liquidation Reveal:
  ✓ requestLiquidationReveal sets pendingReveal and emits LiquidationRevealRequested
  ✓ publicDecryptEbool confirms position is not liquidatable
  ✓ verifyLiquidationReveal emits LiquidationAlertPublic and clears pendingReveal
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
npm install
npm run dev   # http://localhost:5173
```

Connect MetaMask to Sepolia. The deployed contract address is already configured in `frontend/src/config.ts`.

---

## Deployment

Deploy to Sepolia:

```bash
npx hardhat deploy --network sepolia
```

Generate Etherscan verification input:

```bash
node -e "
const fs = require('fs');
const f = fs.readdirSync('artifacts/build-info').find(f => f.endsWith('.json'));
const bi = JSON.parse(fs.readFileSync('artifacts/build-info/' + f));
fs.writeFileSync('std_input.json', JSON.stringify(bi.input, null, 2));
"
```

Upload `std_input.json` to Etherscan → Verify & Publish → Solidity (Standard-Json-Input).

---

## Stack

| Layer | Technology |
|-------|------------|
| FHE Contract Library | `@fhevm/solidity` v0.11.1 |
| FHE Client SDK | `@zama-fhe/relayer-sdk` v0.4.1 |
| Smart Contract | Solidity 0.8.24 + OpenZeppelin |
| Network | Ethereum Sepolia |
| Frontend | React + Vite + ethers.js v6 |
| Testing | Hardhat + fhEVM mock coprocessor |

---

## What Makes ShieldLend Different

Most DeFi lending protocols compute collateral ratios in plaintext, making every position visible on-chain. ShieldLend moves all arithmetic — addition, multiplication, division, comparison — inside FHE ciphertexts. The protocol enforces the 150% collateral requirement and liquidation threshold **homomorphically**: the health check produces an encrypted boolean that is only revealed (via the Zama KMS relayer) when needed for liquidation, and even then only reveals a single bit — not the underlying amounts.

---

## License

MIT
