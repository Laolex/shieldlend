# 🔐 ShieldPay — Confidential On-Chain Payroll

> Built for the **Zama Protocol FHE Hackathon** · Powered by Fully Homomorphic Encryption (fhEVM)

[![Zama fhEVM](https://img.shields.io/badge/Built%20with-Zama%20fhEVM-blueviolet)](https://docs.zama.ai)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue)](https://soliditylang.org)
[![Tests](https://img.shields.io/badge/Tests-27%2F27%20passing-brightgreen)]()
[![Network](https://img.shields.io/badge/Network-Sepolia-orange)]()

**Deployed contract:**
[`0x0AC5A3D3b0787BC97F101a75854bbEC62EE97cc6`](https://sepolia.etherscan.io/address/0x0AC5A3D3b0787BC97F101a75854bbEC62EE97cc6)

---

## The Problem

Public blockchains are radically transparent. For payroll, this means every salary, bonus, and tax amount is visible to
anyone — competitors, employees, and the public. Traditional solutions move computation off-chain, sacrificing
verifiability.

ShieldPay solves this without compromise.

---

## The Solution

ShieldPay runs **fully encrypted payroll arithmetic directly on-chain** using Zama's fhEVM. Salaries, bonuses, and tax
withholdings are stored and computed as FHE ciphertexts — never decrypted on-chain, never exposed in transaction data.

### How the FHE math works

```
gross     = encSalary + encBonus          // FHE.add
tax       = gross >> 2                    // FHE.shr  (≈25% withholding)
netPayout = gross - tax                   // FHE.sub
```

All three operations execute on encrypted values. The contract never sees plaintext amounts.

---

## Architecture

```
Employer (wallet)
    │
    ├─ addEmployee(address, encryptedSalary, inputProof)
    ├─ setBonus(address, encryptedBonus, inputProof)
    └─ executePayrollCycle()
            │
            ▼
    ConfidentialPayroll.sol  (@fhevm/solidity v0.11.1)
    ├─ ZamaEthereumConfig (sets FHE coprocessor)
    ├─ AccessControlEnumerable (EMPLOYER_ROLE, AUDITOR_ROLE)
    ├─ FHE.add / FHE.shr / FHE.sub  (encrypted arithmetic)
    ├─ FHE.allow(handle, address)   (ACL-based access control)
    └─ euint64 storage              (ciphertexts only)
            │
            ▼
    Zama Coprocessor (Sepolia)
    └─ Executes FHE operations off-chain, posts proofs on-chain

Employee (wallet)
    └─ reencrypt(handle) via Zama Relayer → plaintext salary (locally only)
```

---

## Key Features

- **Encrypted salaries and bonuses** — stored as `euint64` ciphertexts, never plaintext
- **On-chain FHE arithmetic** — tax computation and net pay calculated without decryption
- **Role-based access** — `EMPLOYER_ROLE` manages payroll, `AUDITOR_ROLE` for compliance
- **ACL permissions** — each employee can only decrypt their own data via `FHE.allow`
- **Employer-wide access** — `_allowEmployers()` grants all current employers ACL access
- **Full audit trail** — `PayrollCycleExecuted`, `EmployeeAdded`, `SalaryUpdated` events
- **Reencrypt flow** — employees decrypt salaries client-side via EIP-712 + Zama relayer

---

## Contract Functions

| Function                                 | Description                             |
| ---------------------------------------- | --------------------------------------- |
| `addEmployee(addr, handle, proof, dept)` | Enroll employee with encrypted salary   |
| `updateSalary(addr, handle, proof)`      | Update salary (encrypted)               |
| `setBonus(addr, handle, proof)`          | Set one-time encrypted bonus            |
| `executePayrollCycle()`                  | Run payroll for all active employees    |
| `getEncryptedSalary(addr)`               | Returns `euint64` handle (ACL-gated)    |
| `getEncryptedTotalPaid(addr)`            | Returns cumulative encrypted total paid |
| `getEncryptedTaxWithheld(addr)`          | Returns cumulative encrypted tax        |

---

## Test Results

```
27 passing  (0 failing)

✓ Deployment & roles
✓ Add employee with encrypted salary
✓ Update salary
✓ Set and clear bonus
✓ Execute payroll cycle — FHE arithmetic verified
✓ core FHE math: salary 5000 + bonus 1000 → net 4500 after 25% tax
✓ Multi-employee payroll
✓ Access control enforcement
✓ Auditor role
✓ Pause / unpause
```

---

## Local Setup

```bash
git clone https://github.com/Laolex/shieldpay
cd shieldpay
npm install

# Run tests (uses fhEVM mock coprocessor)
npx hardhat test

# Deploy to Sepolia
npx hardhat run scripts/deployShieldPay.ts --network sepolia
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build
npm run preview
```

Requires Rabby or MetaMask on Sepolia. Decryption requires the Zama relayer (`relayer.testnet.zama.org`) to be
reachable.

---

## Technical Stack

| Layer          | Technology                             |
| -------------- | -------------------------------------- |
| FHE Library    | `@fhevm/solidity` v0.11.1              |
| FHE Client     | `@zama-fhe/relayer-sdk` v0.4.1         |
| Smart Contract | Solidity 0.8.24                        |
| Access Control | OpenZeppelin `AccessControlEnumerable` |
| Network        | Ethereum Sepolia testnet               |
| Frontend       | React + Vite + ethers.js v6            |
| Testing        | Hardhat + fhEVM mock coprocessor       |

---

## Decryption Flow

1. Employee clicks **Decrypt Salary**
2. Browser generates ephemeral keypair via `fhevmInst.generateKeypair()`
3. Employee signs EIP-712 message with their wallet (proves ownership)
4. `fhevmInst.reencrypt()` sends the handle + signature to the Zama relayer
5. Relayer re-encrypts the ciphertext under the ephemeral public key
6. Browser decrypts locally using the ephemeral private key
7. Plaintext salary displayed — never stored, never sent to any server

---

## License

MIT
