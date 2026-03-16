import { ethers, fhevm } from "hardhat";
import { expect } from "chai";
import { ConfidentialLending } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

import { FhevmType } from "@fhevm/hardhat-plugin";

let contract: ConfidentialLending;
let contractAddress: string;
let admin: HardhatEthersSigner;
let borrower1: HardhatEthersSigner;
let borrower2: HardhatEthersSigner;
let liquidator: HardhatEthersSigner;

async function encryptUint64(signer: HardhatEthersSigner, amount: bigint) {
  const r = await fhevm.encryptUint(FhevmType.euint64, amount, contractAddress, signer.address);
  return {
    externalEuint: ethers.hexlify(r.externalEuint as any),
    inputProof: ethers.hexlify(r.inputProof as any),
  };
}

async function decrypt(handle: bigint, signer: HardhatEthersSigner): Promise<bigint> {
  return fhevm.userDecryptEuint(FhevmType.euint64, handle, contractAddress, signer);
}

describe("ConfidentialLending", function () {
  before(async function () {
    [admin, borrower1, borrower2, liquidator] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("ConfidentialLending");
    contract = await factory.deploy();
    await contract.waitForDeployment();
    contractAddress = await contract.getAddress();

    // Grant liquidator role
    await contract.grantLiquidatorRole(liquidator.address);
  });

  // ── Deployment ────────────────────────────────────────────────────────────
  describe("Deployment", function () {
    it("deploys with correct roles", async function () {
      const ADMIN_ROLE = await contract.ADMIN_ROLE();
      const LIQUIDATOR_ROLE = await contract.LIQUIDATOR_ROLE();
      expect(await contract.hasRole(ADMIN_ROLE, admin.address)).to.be.true;
      expect(await contract.hasRole(LIQUIDATOR_ROLE, liquidator.address)).to.be.true;
    });

    it("starts with zero borrowers", async function () {
      expect(await contract.getBorrowerCount()).to.equal(0n);
    });
  });

  // ── Deposit ───────────────────────────────────────────────────────────────
  describe("Deposit", function () {
    it("allows borrower to deposit collateral", async function () {
      const collateral = 10000n; // 10000 wei
      const { externalEuint, inputProof } = await encryptUint64(borrower1, collateral);
      const c = contract.connect(borrower1);
      const tx = await c.deposit(externalEuint, inputProof, { value: collateral });
      await tx.wait();
      expect(await contract.isActive(borrower1.address)).to.be.true;
      expect(await contract.getBorrowerCount()).to.equal(1n);
    });

    it("encrypts collateral correctly", async function () {
      const handle = await contract.getEncryptedCollateral(borrower1.address);
      const decrypted = await decrypt(handle, borrower1);
      expect(decrypted).to.equal(10000n);
    });

    it("allows adding more collateral", async function () {
      const extra = 5000n;
      const { externalEuint, inputProof } = await encryptUint64(borrower1, extra);
      await (await contract.connect(borrower1).deposit(externalEuint, inputProof, { value: extra })).wait();
      const handle = await contract.getEncryptedCollateral(borrower1.address);
      const decrypted = await decrypt(handle, borrower1);
      expect(decrypted).to.equal(15000n);
    });

    it("second borrower can deposit independently", async function () {
      const { externalEuint, inputProof } = await encryptUint64(borrower2, 20000n);
      await (await contract.connect(borrower2).deposit(externalEuint, inputProof, { value: 20000n })).wait();
      expect(await contract.getBorrowerCount()).to.equal(2n);
    });
  });

  // ── Borrow ────────────────────────────────────────────────────────────────
  describe("Borrow", function () {
    it("allows borrowing against collateral", async function () {
      const loanAmount = 5000n; // borrow 5000 against 15000 collateral (~33%)
      const { externalEuint, inputProof } = await encryptUint64(borrower1, loanAmount);
      await (await contract.connect(borrower1).borrow(externalEuint, inputProof)).wait();
      const handle = await contract.getEncryptedLoanAmount(borrower1.address);
      const decrypted = await decrypt(handle, borrower1);
      expect(decrypted).to.equal(5000n);
    });

    it("encrypts total debt correctly", async function () {
      const handle = await contract.getEncryptedTotalDebt(borrower1.address);
      const decrypted = await decrypt(handle, borrower1);
      expect(decrypted).to.equal(5000n);
    });

    it("position is not liquidatable at safe ratio", async function () {
      // collateral=15000, debt=5000 → 300% collateral ratio → safe
      const handle = await contract.getIsLiquidatable(borrower1.address);
      const isLiq = await fhevm.userDecryptEbool(handle, contractAddress, borrower1);
      expect(isLiq).to.be.false;
    });

    it("reverts if no collateral deposited", async function () {
      const [,,, , stranger] = await ethers.getSigners();
      const { externalEuint, inputProof } = await encryptUint64(stranger, 1000n);
      await expect(contract.connect(stranger).borrow(externalEuint, inputProof))
        .to.be.revertedWith("No collateral deposited");
    });
  });

  // ── Interest accrual ──────────────────────────────────────────────────────
  describe("Interest accrual", function () {
    it("accrues interest on debt", async function () {
      const debtBefore = await decrypt(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      await (await contract.accrueInterest(borrower1.address)).wait();
      const debtAfter = await decrypt(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      // interest = 5000 * 500 / 10000 = 250 → debt = 5250
      expect(debtAfter).to.equal(debtBefore + 250n);
    });
  });

  // ── Credit score ──────────────────────────────────────────────────────────
  describe("Credit score", function () {
    it("admin can update credit score", async function () {
      const score = 800n;
      const { externalEuint, inputProof } = await encryptUint64(admin, score);
      await (await contract.updateCreditScore(borrower1.address, externalEuint, inputProof)).wait();
      const handle = await contract.getEncryptedCreditScore(borrower1.address);
      const decrypted = await decrypt(handle, borrower1);
      expect(decrypted).to.equal(800n);
    });

    it("higher credit score lowers interest rate", async function () {
      // rate = BASE_RATE(500) - score/2/100 = 500 - 400/100 = 500 - 4 = 496
      const handle = await contract.getEncryptedInterestRate(borrower1.address);
      const rate = await decrypt(handle, borrower1);
      expect(rate).to.be.lt(500n); // lower than base rate
    });
  });

  // ── Repay ─────────────────────────────────────────────────────────────────
  describe("Repay", function () {
    it("allows partial repayment", async function () {
      const debtBefore = await decrypt(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      const repayAmt = 1000n;
      const { externalEuint, inputProof } = await encryptUint64(borrower1, repayAmt);
      await (await contract.connect(borrower1).repay(externalEuint, inputProof)).wait();
      const debtAfter = await decrypt(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      expect(debtAfter).to.equal(debtBefore - repayAmt);
    });
  });

  // ── Liquidation ───────────────────────────────────────────────────────────
  describe("Liquidation", function () {
    it("liquidator can liquidate a position", async function () {
      await (await contract.connect(liquidator).liquidate(borrower2.address)).wait();
      expect(await contract.isActive(borrower2.address)).to.be.false;
    });

    it("non-liquidator cannot liquidate", async function () {
      await expect(contract.connect(borrower1).liquidate(borrower1.address))
        .to.be.reverted;
    });
  });

  // ── FHE core math ─────────────────────────────────────────────────────────
  describe("★ core FHE math", function () {
    it("health factor: collateral 30000, debt 10000 → not liquidatable", async function () {
      const [,,,,,fresh] = await ethers.getSigners();
      const { externalEuint: ce, inputProof: cp } = await encryptUint64(fresh, 30000n);
      await (await contract.connect(fresh).deposit(ce, cp, { value: 30000n })).wait();
      const { externalEuint: be, inputProof: bp } = await encryptUint64(fresh, 10000n);
      await (await contract.connect(fresh).borrow(be, bp)).wait();
      // collateral*100=3000000 vs debt*150=1500000 → not liquidatable
      const handle = await contract.getIsLiquidatable(fresh.address);
      const isLiq = await fhevm.userDecryptEbool(handle, contractAddress, fresh);
      expect(isLiq).to.be.false;
    });

    it("interest: debt 10000 * rate 500bps / 10000 = 500 interest", async function () {
      const [,,,,,,fresh2] = await ethers.getSigners();
      const { externalEuint: ce, inputProof: cp } = await encryptUint64(fresh2, 50000n);
      await (await contract.connect(fresh2).deposit(ce, cp, { value: 50000n })).wait();
      const { externalEuint: be, inputProof: bp } = await encryptUint64(fresh2, 10000n);
      await (await contract.connect(fresh2).borrow(be, bp)).wait();
      await (await contract.accrueInterest(fresh2.address)).wait();
      const debt = await decrypt(await contract.getEncryptedTotalDebt(fresh2.address), fresh2);
      expect(debt).to.equal(10500n); // 10000 + 500 interest
    });
  });

  // ── Pause ─────────────────────────────────────────────────────────────────
  describe("Pause", function () {
    it("admin can pause and unpause", async function () {
      await (await contract.pause()).wait();
      const { externalEuint, inputProof } = await encryptUint64(borrower1, 1000n);
      await expect(contract.connect(borrower1).deposit(externalEuint, inputProof, { value: 1000n }))
        .to.be.reverted;
      await (await contract.unpause()).wait();
    });
  });
});
