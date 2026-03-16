# 🔐 ShieldPay — Confidential On-Chain Payroll

> Built for the **Zama fhEVM Hackathon** · Powered by Fully Homomorphic Encryption

[![Zama fhEVM](https://img.shields.io/badge/Built%20with-Zama%20fhEVM-blueviolet)](https://docs.zama.ai)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue)](https://soliditylang.org)
[![Tests](https://img.shields.io/badge/Tests-27%2F27%20passing-brightgreen)]()
[![Network](https://img.shields.io/badge/Network-Sepolia-orange)]()

**Contract:**
[`0x0AC5A3D3b0787BC97F101a75854bbEC62EE97cc6`](https://sepolia.etherscan.io/address/0x0AC5A3D3b0787BC97F101a75854bbEC62EE97cc6)  
**Frontend:**
[shieldpay-delta.vercel.app](https://shieldpay-delta.vercel.app)

---

## The Problem

Public blockchains are radically transparent. Every salary, bonus, and tax payment is visible to anyone — employees see
each other's pay, competitors infer burn rate, and sensitive financial data is permanently public.

ShieldPay solves this using Fully Homomorphic Encryption. Payroll arithmetic runs entirely on encrypted values,
on-chain, with zero plaintext ever touching the blockchain.

---

## How It Works

### Encrypted Payroll Arithmetic

```
encGross  = FHE.add(encSalary, encBonus)   // add encrypted values
encTax    = FHE.shr(encGross, 2)           // right-shift = ÷4 ≈ 25% withholding
encNet    = FHE.sub(encGross, encTax)      // subtract encrypted tax
```

All three operations execute directly on `euint64` ciphertexts. The contract never sees plaintext amounts at any point.

### Encryption Flow (Client → Chain)

```
Browser (fhevmjs)
  └─ encryptUint(salary, contractAddress, userAddress)
       → externalEuint64 handle + ZK inputProof
            │
            ▼
  ConfidentialPayroll.sol
  └─ FHE.fromExternal(handle, inputProof)  // verify + store as euint64
  └─ FHE.allow(euint64, employeeAddress)   // grant ACL access
  └─ FHE.allowThis(euint64)                // contract retains access
```

### Decryption Flow (Chain → Employee)

```
Employee wallet signs EIP-712 message (proves ownership)
  └─ fhevmInst.generateKeypair()           // ephemeral keypair in browser
  └─ fhevmInst.createEIP712(pubKey, contractAddress)
  └─ wallet.signTypedData(eip712)
  └─ fhevmInst.reencrypt(handle, privKey, pubKey, signature, contract, account)
       │
       ▼
  Zama Relayer (relayer.testnet.zama.org)
  └─ Verifies ACL permission on-chain
  └─ Re-encrypts ciphertext under employee ephemeral pubKey
  └─ Returns encrypted value → browser decrypts locally
       │
       ▼
  Plaintext salary — never stored, never transmitted, visible only in browser memory
```

> **Testnet note:** The Zama testnet relayer does not currently send CORS headers, blocking browser-initiated reencrypt
> requests. The decryption logic is fully implemented and correct — this is a testnet infrastructure limitation. The
> flow works end-to-end in the Hardhat test environment using `userDecryptEuint`.

---

## Contract Architecture

```
ConfidentialPayroll.sol
├── ZamaEthereumConfig          // sets FHE coprocessor addresses
├── AccessControlEnumerable     // EMPLOYER_ROLE, AUDITOR_ROLE
├── ReentrancyGuard
│
├── Storage (all encrypted)
│   ├── euint64 baseSalary
│   ├── euint64 bonus
│   ├── euint64 totalPaid       // cumulative
│   └── euint64 taxWithheld     // cumulative
│
├── Payroll Logic
│   ├── addEmployee()           // encrypt + store salary, grant ACL
│   ├── setBonus()              // encrypt + store bonus
│   ├── executePayrollCycle()   // FHE.add / FHE.shr / FHE.sub on all employees
│   └── _allowEmployers()       // grant ACL to all current employers
│
└── View Functions (ACL-gated)
    ├── getEncryptedSalary()
    ├── getEncryptedTotalPaid()
    └── getEncryptedTaxWithheld()
```

---

## Test Results

```
27 passing  (0 failing)

Core FHE math:
  ✓ salary 5000 + bonus 1000 = gross 6000
  ✓ tax = 6000 >> 2 = 1500  (25% via FHE.shr)
  ✓ net = 6000 - 1500 = 4500
  ✓ totalPaid accumulates correctly across cycles
  ✓ taxWithheld accumulates correctly

Access control:
  ✓ EMPLOYER_ROLE gates all payroll operations
  ✓ employees can only decrypt their own salary (ACL)
  ✓ auditors can read encrypted handles

Other:
  ✓ pause / unpause
  ✓ multi-employee payroll cycle
  ✓ bonus clears after each cycle
```

---

## Local Setup

```bash
git clone https://github.com/Laolex/shieldpay
cd shieldpay
npm install
npx hardhat test
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

---

## Stack

| Layer                | Technology                       |
| -------------------- | -------------------------------- |
| FHE Contract Library | `@fhevm/solidity` v0.11.1        |
| FHE Client SDK       | `@zama-fhe/relayer-sdk` v0.4.1   |
| Smart Contract       | Solidity 0.8.24 + OpenZeppelin   |
| Network              | Ethereum Sepolia                 |
| Frontend             | React + Vite + ethers.js v6      |
| Testing              | Hardhat + fhEVM mock coprocessor |

---

## What Makes ShieldPay Different

Most "confidential payroll" solutions encrypt data off-chain and store hashes on-chain. ShieldPay performs the actual
arithmetic — addition, division, subtraction — inside FHE ciphertexts, on-chain, verified by the Zama coprocessor. No
trusted intermediary ever sees plaintext payroll data.

---

## License

MIT
