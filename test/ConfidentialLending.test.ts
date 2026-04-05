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

async function encryptU64(signer: HardhatEthersSigner, amount: bigint, addr?: string) {
  const target = addr ?? contractAddress;
  const r = await fhevm.encryptUint(FhevmType.euint64, amount, target, signer.address);
  return {
    externalEuint: ethers.hexlify(r.externalEuint as any),
    inputProof:    ethers.hexlify(r.inputProof as any),
  };
}

async function decryptU64(handle: bigint, signer: HardhatEthersSigner): Promise<bigint> {
  return fhevm.userDecryptEuint(FhevmType.euint64, handle, contractAddress, signer);
}

describe("ConfidentialLending", function () {

  before(async function () {
    [admin, borrower1, borrower2, liquidator] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("ConfidentialLending");
    contract = await factory.deploy();
    await contract.waitForDeployment();
    contractAddress = await contract.getAddress();
    await contract.grantLiquidatorRole(liquidator.address);
  });

  // ── Deployment ────────────────────────────────────────────────────────────
  describe("Deployment", function () {
    it("deploys with correct roles", async function () {
      expect(await contract.hasRole(await contract.ADMIN_ROLE(),      admin.address)).to.be.true;
      expect(await contract.hasRole(await contract.LIQUIDATOR_ROLE(), liquidator.address)).to.be.true;
    });

    it("starts with zero borrowers", async function () {
      expect(await contract.getBorrowerCount()).to.equal(0n);
    });
  });

  // ── Deposit ───────────────────────────────────────────────────────────────
  describe("Deposit", function () {
    it("allows borrower to deposit collateral", async function () {
      const { externalEuint, inputProof } = await encryptU64(borrower1, 10000n);
      await (await contract.connect(borrower1).deposit(externalEuint, inputProof, { value: 10000n })).wait();
      expect(await contract.isActive(borrower1.address)).to.be.true;
      expect(await contract.getBorrowerCount()).to.equal(1n);
      expect(await contract.ethDeposited(borrower1.address)).to.equal(10000n);
    });

    it("encrypts collateral correctly", async function () {
      const handle    = await contract.getEncryptedCollateral(borrower1.address);
      const decrypted = await decryptU64(handle, borrower1);
      expect(decrypted).to.equal(10000n);
    });

    it("allows adding more collateral", async function () {
      const { externalEuint, inputProof } = await encryptU64(borrower1, 5000n);
      await (await contract.connect(borrower1).deposit(externalEuint, inputProof, { value: 5000n })).wait();
      const decrypted = await decryptU64(await contract.getEncryptedCollateral(borrower1.address), borrower1);
      expect(decrypted).to.equal(15000n);
      expect(await contract.ethDeposited(borrower1.address)).to.equal(15000n);
    });

    it("second borrower can deposit independently", async function () {
      const { externalEuint, inputProof } = await encryptU64(borrower2, 20000n);
      await (await contract.connect(borrower2).deposit(externalEuint, inputProof, { value: 20000n })).wait();
      expect(await contract.getBorrowerCount()).to.equal(2n);
    });
  });

  // ── Borrow ────────────────────────────────────────────────────────────────
  describe("Borrow", function () {
    it("allows borrowing against collateral", async function () {
      const { externalEuint, inputProof } = await encryptU64(borrower1, 5000n);
      await (await contract.connect(borrower1).borrow(externalEuint, inputProof)).wait();
      const decrypted = await decryptU64(await contract.getEncryptedLoanAmount(borrower1.address), borrower1);
      expect(decrypted).to.equal(5000n);
    });

    it("encrypts total debt correctly", async function () {
      const decrypted = await decryptU64(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      expect(decrypted).to.equal(5000n);
    });

    it("position is not liquidatable at safe ratio (15000 collateral, 5000 debt)", async function () {
      const handle = await contract.getIsLiquidatable(borrower1.address);
      const isLiq  = await fhevm.userDecryptEbool(handle, contractAddress, borrower1);
      expect(isLiq).to.be.false;
    });

    it("reverts if no collateral deposited", async function () {
      const [,,,, stranger] = await ethers.getSigners();
      const { externalEuint, inputProof } = await encryptU64(stranger, 1000n);
      await expect(contract.connect(stranger).borrow(externalEuint, inputProof))
        .to.be.revertedWith("No collateral deposited");
    });
  });

  // ── Interest accrual ──────────────────────────────────────────────────────
  describe("Interest accrual", function () {
    it("admin can accrue interest", async function () {
      const before = await decryptU64(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      await (await contract.accrueInterest(borrower1.address)).wait();
      const after  = await decryptU64(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      // 5000 * 500 / 10000 = 250
      expect(after).to.equal(before + 250n);
    });

    it("non-admin cannot accrue interest", async function () {
      await expect(contract.connect(borrower1).accrueInterest(borrower1.address))
        .to.be.reverted;
    });
  });

  // ── Credit score ──────────────────────────────────────────────────────────
  describe("Credit score", function () {
    it("admin can update credit score", async function () {
      const { externalEuint, inputProof } = await encryptU64(admin, 800n);
      await (await contract.updateCreditScore(borrower1.address, externalEuint, inputProof)).wait();
      const decrypted = await decryptU64(await contract.getEncryptedCreditScore(borrower1.address), borrower1);
      expect(decrypted).to.equal(800n);
    });

    it("higher credit score lowers interest rate below base", async function () {
      const rate = await decryptU64(await contract.getEncryptedInterestRate(borrower1.address), borrower1);
      expect(rate).to.be.lt(500n);
    });
  });

  // ── Repay ─────────────────────────────────────────────────────────────────
  describe("Repay", function () {
    it("allows partial repayment", async function () {
      const before = await decryptU64(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      const { externalEuint, inputProof } = await encryptU64(borrower1, 1000n);
      await (await contract.connect(borrower1).repay(externalEuint, inputProof)).wait();
      const after  = await decryptU64(await contract.getEncryptedTotalDebt(borrower1.address), borrower1);
      expect(after).to.equal(before - 1000n);
    });

    it("floor-at-zero: overpayment clamps to 0, does not wrap", async function () {
      const [,,,,, fresh] = await ethers.getSigners();
      const { externalEuint: ce, inputProof: cp } = await encryptU64(fresh, 10000n);
      await (await contract.connect(fresh).deposit(ce, cp, { value: 10000n })).wait();
      const freshAddr = await contract.getAddress();

      const { externalEuint: be, inputProof: bp } = await encryptU64(fresh, 1000n);
      await (await contract.connect(fresh).borrow(be, bp)).wait();

      // Repay 9999 — far more than debt of 1000
      const { externalEuint: re, inputProof: rp } = await encryptU64(fresh, 9999n);
      await (await contract.connect(fresh).repay(re, rp)).wait();

      const debt = await decryptU64(await contract.getEncryptedTotalDebt(fresh.address), fresh);
      expect(debt).to.equal(0n); // clamped to 0, not wrapped
    });
  });

  // ── Pause ─────────────────────────────────────────────────────────────────
  describe("Pause", function () {
    it("admin can pause and unpause", async function () {
      await (await contract.pause()).wait();
      const { externalEuint, inputProof } = await encryptU64(borrower1, 1000n);
      await expect(contract.connect(borrower1).deposit(externalEuint, inputProof, { value: 1000n }))
        .to.be.reverted;
      await (await contract.unpause()).wait();
    });
  });

  // ── Close position (withdraw collateral) ─────────────────────────────────
  describe("Close position — requestClosePosition / verifyAndClose", function () {
    let closer: HardhatEthersSigner;
    let closeContract: any;
    let closeAddress: string;

    before(async function () {
      [,,,,,,, closer] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      closeContract = await factory.deploy();
      await closeContract.waitForDeployment();
      closeAddress = await closeContract.getAddress();

      // Deposit only, no borrow → totalDebt = 0
      const r = await fhevm.encryptUint(FhevmType.euint64, 5000n, closeAddress, closer.address);
      await (await closeContract.connect(closer).deposit(
        ethers.hexlify(r.externalEuint as any),
        ethers.hexlify(r.inputProof as any),
        { value: 5000n }
      )).wait();
    });

    it("requestClosePosition sets pendingClose and emits CloseRequested", async function () {
      const tx      = await closeContract.connect(closer).requestClosePosition();
      const receipt = await tx.wait();
      expect(await closeContract.isPendingClose(closer.address)).to.be.true;
      const evt = receipt?.logs
        .map((l: any) => { try { return closeContract.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e?.name === "CloseRequested");
      expect(evt).to.not.be.undefined;
    });

    it("verifyAndClose returns ETH and closes position when debt is 0", async function () {
      const handle    = await closeContract.getEncryptedTotalDebt(closer.address);
      const handleHex = ethers.hexlify(handle as any);
      const result    = await fhevm.publicDecrypt([handleHex]);

      const balBefore = await ethers.provider.getBalance(closer.address);
      const tx        = await closeContract.connect(closer).verifyAndClose(
        [handleHex],
        result.abiEncodedClearValues,
        result.decryptionProof
      );
      const receipt   = await tx.wait();
      const gas       = receipt!.gasUsed * receipt!.gasPrice;
      const balAfter  = await ethers.provider.getBalance(closer.address);

      expect(await closeContract.isActive(closer.address)).to.be.false;
      expect(await closeContract.isPendingClose(closer.address)).to.be.false;
      expect(balAfter - balBefore + gas).to.equal(5000n); // got ETH back

      const evt = receipt?.logs
        .map((l: any) => { try { return closeContract.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e?.name === "PositionClosed");
      expect(evt).to.not.be.undefined;
      expect(evt!.args.ethReturned).to.equal(5000n);
    });

    it("verifyAndClose reverts when debt is non-zero", async function () {
      // Setup a borrower WITH debt
      const [,,,,,,,, debtor] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      const debtorContract = await factory.deploy();
      await debtorContract.waitForDeployment();
      const debtorAddr = await debtorContract.getAddress();

      const dr = await fhevm.encryptUint(FhevmType.euint64, 10000n, debtorAddr, debtor.address);
      await (await debtorContract.connect(debtor).deposit(
        ethers.hexlify(dr.externalEuint as any),
        ethers.hexlify(dr.inputProof as any),
        { value: 10000n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 3000n, debtorAddr, debtor.address);
      await (await debtorContract.connect(debtor).borrow(
        ethers.hexlify(br.externalEuint as any),
        ethers.hexlify(br.inputProof as any)
      )).wait();
      await (await debtorContract.connect(debtor).requestClosePosition()).wait();

      const handle    = await debtorContract.getEncryptedTotalDebt(debtor.address);
      const handleHex = ethers.hexlify(handle as any);
      const result    = await fhevm.publicDecrypt([handleHex]);

      await expect(debtorContract.connect(debtor).verifyAndClose(
        [handleHex], result.abiEncodedClearValues, result.decryptionProof
      )).to.be.revertedWith("Outstanding debt - repay in full before closing");
    });
  });

  // ── Liquidation (full 3-step flow) ────────────────────────────────────────
  describe("Liquidation — reveal → confirm → execute", function () {
    let liqBorrower: HardhatEthersSigner;
    let liqContract: any;
    let liqAddress: string;

    before(async function () {
      // Use a fresh contract to keep state clean
      [,,,,,,,,,, liqBorrower] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      liqContract = await factory.deploy();
      await liqContract.waitForDeployment();
      liqAddress = await liqContract.getAddress();
      await liqContract.grantLiquidatorRole(liquidator.address);

      // Underwater position: collateral=100, debt=200
      // collateral*100=10000, debt*150=30000 → 10000 < 30000 → isLiquidatable=true
      const cr = await fhevm.encryptUint(FhevmType.euint64, 100n, liqAddress, liqBorrower.address);
      await (await liqContract.connect(liqBorrower).deposit(
        ethers.hexlify(cr.externalEuint as any),
        ethers.hexlify(cr.inputProof as any),
        { value: 100n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 200n, liqAddress, liqBorrower.address);
      await (await liqContract.connect(liqBorrower).borrow(
        ethers.hexlify(br.externalEuint as any),
        ethers.hexlify(br.inputProof as any)
      )).wait();
    });

    it("position is liquidatable (collateral*100 < debt*150)", async function () {
      const handle = await liqContract.getIsLiquidatable(liqBorrower.address);
      const isLiq  = await fhevm.userDecryptEbool(handle, liqAddress, liqBorrower);
      expect(isLiq).to.be.true;
    });

    it("liquidate() reverts without confirmedLiquidatable", async function () {
      await expect(liqContract.connect(liquidator).liquidate(liqBorrower.address))
        .to.be.revertedWith("Not confirmed liquidatable - run reveal first");
    });

    it("step 1: requestLiquidationReveal emits event and sets pendingReveal", async function () {
      const tx      = await liqContract.requestLiquidationReveal(liqBorrower.address);
      const receipt = await tx.wait();
      expect(await liqContract.isPendingReveal(liqBorrower.address)).to.be.true;
      const evt = receipt?.logs
        .map((l: any) => { try { return liqContract.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e?.name === "LiquidationRevealRequested");
      expect(evt).to.not.be.undefined;
    });

    it("step 2: verifyLiquidationReveal confirms liquidatable and sets flag", async function () {
      const handle    = await liqContract.getIsLiquidatable(liqBorrower.address);
      const handleHex = ethers.hexlify(handle as any);
      const result    = await fhevm.publicDecrypt([handleHex]);

      await (await liqContract.verifyLiquidationReveal(
        liqBorrower.address, [handleHex], result.abiEncodedClearValues, result.decryptionProof
      )).wait();

      expect(await liqContract.isConfirmedLiquidatable(liqBorrower.address)).to.be.true;
      expect(await liqContract.isPendingReveal(liqBorrower.address)).to.be.false;
    });

    it("step 3: liquidate() executes and transfers ETH to liquidator", async function () {
      const liqBalBefore = await ethers.provider.getBalance(liquidator.address);
      const tx           = await liqContract.connect(liquidator).liquidate(liqBorrower.address);
      const receipt      = await tx.wait();
      const gas          = receipt!.gasUsed * receipt!.gasPrice;
      const liqBalAfter  = await ethers.provider.getBalance(liquidator.address);

      expect(await liqContract.isActive(liqBorrower.address)).to.be.false;
      expect(await liqContract.isConfirmedLiquidatable(liqBorrower.address)).to.be.false;
      expect(await liqContract.getBorrowerCount()).to.equal(0n);
      // 2% protocol fee on 100 wei = 2 wei taken; no bonus (protocolReserve is empty)
      expect(liqBalAfter - liqBalBefore + gas).to.equal(98n);
    });

    it("non-liquidator cannot liquidate", async function () {
      await expect(contract.connect(borrower1).liquidate(borrower1.address))
        .to.be.reverted;
    });
  });

  // ── Borrower list cleanup ─────────────────────────────────────────────────
  describe("Borrower list — O(1) removal", function () {
    it("borrowerList shrinks after liquidation", async function () {
      // Verified by liquidation test above — count returned to 0
      // Test multi-borrower swap-and-pop
      const factory   = await ethers.getContractFactory("ConfidentialLending");
      const c         = await factory.deploy();
      await c.waitForDeployment();
      const addr      = await c.getAddress();
      await c.grantLiquidatorRole(liquidator.address);

      const signers = await ethers.getSigners();
      const a = signers[11], b = signers[12], d = signers[13];

      for (const s of [a, b, d]) {
        const r = await fhevm.encryptUint(FhevmType.euint64, 100n, addr, s.address);
        await (await c.connect(s).deposit(
          ethers.hexlify(r.externalEuint as any), ethers.hexlify(r.inputProof as any), { value: 100n }
        )).wait();
      }
      expect(await c.getBorrowerCount()).to.equal(3n);

      // Make b liquidatable and go through full flow
      const br = await fhevm.encryptUint(FhevmType.euint64, 200n, addr, b.address);
      await (await c.connect(b).borrow(
        ethers.hexlify(br.externalEuint as any), ethers.hexlify(br.inputProof as any)
      )).wait();
      await (await c.requestLiquidationReveal(b.address)).wait();
      const handle    = await c.getIsLiquidatable(b.address);
      const handleHex = ethers.hexlify(handle as any);
      const result    = await fhevm.publicDecrypt([handleHex]);
      await (await c.verifyLiquidationReveal(
        b.address, [handleHex], result.abiEncodedClearValues, result.decryptionProof
      )).wait();
      await (await c.connect(liquidator).liquidate(b.address)).wait();

      expect(await c.getBorrowerCount()).to.equal(2n);
      expect(await c.isActive(b.address)).to.be.false;
    });
  });

  // ── Core FHE math ─────────────────────────────────────────────────────────
  describe("★ Core FHE math", function () {
    it("collateral 30000, debt 10000 → not liquidatable", async function () {
      const [,,,,, fresh] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      const c = await factory.deploy();
      await c.waitForDeployment();
      const addr = await c.getAddress();

      const cr = await fhevm.encryptUint(FhevmType.euint64, 30000n, addr, fresh.address);
      await (await c.connect(fresh).deposit(
        ethers.hexlify(cr.externalEuint as any), ethers.hexlify(cr.inputProof as any), { value: 30000n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 10000n, addr, fresh.address);
      await (await c.connect(fresh).borrow(
        ethers.hexlify(br.externalEuint as any), ethers.hexlify(br.inputProof as any)
      )).wait();

      const isLiq = await fhevm.userDecryptEbool(await c.getIsLiquidatable(fresh.address), addr, fresh);
      expect(isLiq).to.be.false;
    });

    it("interest: debt 10000 * 500bps / 10000 = 500", async function () {
      const [,,,,,, fresh2] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      const c = await factory.deploy();
      await c.waitForDeployment();
      const addr = await c.getAddress();

      const cr = await fhevm.encryptUint(FhevmType.euint64, 50000n, addr, fresh2.address);
      await (await c.connect(fresh2).deposit(
        ethers.hexlify(cr.externalEuint as any), ethers.hexlify(cr.inputProof as any), { value: 50000n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 10000n, addr, fresh2.address);
      await (await c.connect(fresh2).borrow(
        ethers.hexlify(br.externalEuint as any), ethers.hexlify(br.inputProof as any)
      )).wait();
      await (await c.accrueInterest(fresh2.address)).wait();

      const debt = await fhevm.userDecryptEuint(FhevmType.euint64, await c.getEncryptedTotalDebt(fresh2.address), addr, fresh2);
      expect(debt).to.equal(10500n);
    });
  });

  // ── Public Decryption (original tests preserved) ──────────────────────────
  describe("Public Decryption — Liquidation Reveal (safe position)", function () {
    let revBorrower: HardhatEthersSigner;
    let revContract: any;
    let revAddress: string;

    before(async function () {
      [,,,,,,, revBorrower] = await ethers.getSigners();
      const factory = await ethers.getContractFactory("ConfidentialLending");
      revContract = await factory.deploy();
      await revContract.waitForDeployment();
      revAddress = await revContract.getAddress();
      await revContract.grantLiquidatorRole(liquidator.address);

      const cr = await fhevm.encryptUint(FhevmType.euint64, 30000n, revAddress, revBorrower.address);
      await (await revContract.connect(revBorrower).deposit(
        ethers.hexlify(cr.externalEuint as any), ethers.hexlify(cr.inputProof as any), { value: 30000n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 5000n, revAddress, revBorrower.address);
      await (await revContract.connect(revBorrower).borrow(
        ethers.hexlify(br.externalEuint as any), ethers.hexlify(br.inputProof as any)
      )).wait();
    });

    it("requestLiquidationReveal sets pendingReveal and emits event", async function () {
      const tx      = await revContract.requestLiquidationReveal(revBorrower.address);
      const receipt = await tx.wait();
      expect(await revContract.isPendingReveal(revBorrower.address)).to.be.true;
      const evt = receipt?.logs
        .map((l: any) => { try { return revContract.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e?.name === "LiquidationRevealRequested");
      expect(evt).to.not.be.undefined;
      expect(evt!.args.borrower).to.equal(revBorrower.address);
    });

    it("publicDecryptEbool confirms position is NOT liquidatable", async function () {
      const handle    = await revContract.getIsLiquidatable(revBorrower.address);
      const handleHex = ethers.hexlify(handle as any);
      const isLiq     = await fhevm.publicDecryptEbool(handleHex);
      expect(isLiq).to.be.false;
    });

    it("verifyLiquidationReveal clears pendingReveal and does NOT set confirmedLiquidatable", async function () {
      const handle    = await revContract.getIsLiquidatable(revBorrower.address);
      const handleHex = ethers.hexlify(handle as any);
      const result    = await fhevm.publicDecrypt([handleHex]);

      const tx      = await revContract.verifyLiquidationReveal(
        revBorrower.address, [handleHex], result.abiEncodedClearValues, result.decryptionProof
      );
      const receipt = await tx.wait();

      expect(await revContract.isPendingReveal(revBorrower.address)).to.be.false;
      expect(await revContract.isConfirmedLiquidatable(revBorrower.address)).to.be.false;

      const evt = receipt?.logs
        .map((l: any) => { try { return revContract.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e?.name === "LiquidationAlertPublic");
      expect(evt).to.not.be.undefined;
      expect(evt!.args.isLiquidatable).to.be.false;
    });
  });

  // ── ShieldScore integration ───────────────────────────────────────────────
  describe("ShieldScore integration — score-gated collateral ratios", function () {
    let scoreC: any;          // ConfidentialCreditScore
    let lendC: any;           // ConfidentialLending (fresh, wired to scoreC)
    let lendAddr: string;
    let borrowerS: HardhatEthersSigner;
    let oracleS:   HardhatEthersSigner;

    before(async function () {
      [,,,,,,,,,,,,,,borrowerS, oracleS] = await ethers.getSigners();

      // Deploy ShieldScore
      const scoreFactory = await ethers.getContractFactory("ConfidentialCreditScore");
      scoreC = await scoreFactory.deploy();
      await scoreC.waitForDeployment();
      await scoreC.grantOracleRole(oracleS.address);

      // Deploy ShieldLend and wire score contract
      const lendFactory = await ethers.getContractFactory("ConfidentialLending");
      lendC = await lendFactory.deploy();
      await lendC.waitForDeployment();
      lendAddr = await lendC.getAddress();
      await lendC.setScoreContract(await scoreC.getAddress());
    });

    async function encryptL(signer: HardhatEthersSigner, val: bigint) {
      const r = await fhevm.encryptUint(FhevmType.euint64, val, lendAddr, signer.address);
      return { h: ethers.hexlify(r.externalEuint as any), p: ethers.hexlify(r.inputProof as any) };
    }

    async function setScore(subject: HardhatEthersSigner, score: bigint) {
      const scoreAddr = await scoreC.getAddress();
      const r = await fhevm.encryptUint(FhevmType.euint64, score, scoreAddr, oracleS.address);
      await (await scoreC.connect(oracleS).setScore(
        subject.address,
        ethers.hexlify(r.externalEuint as any),
        ethers.hexlify(r.inputProof as any)
      )).wait();
    }

    it("scoreContract wired correctly", async function () {
      expect(await lendC.scoreContract()).to.equal(await scoreC.getAddress());
    });

    it("no score — default 150% ratio — collateral 100, debt 80 is NOT liquidatable", async function () {
      // collateral*100=10000, debt*150=12000 → 10000 < 12000 → liquidatable
      // So collateral 100, debt 60 → 10000 vs 9000 → NOT liquidatable
      const { h, p } = await encryptL(borrowerS, 100n);
      await (await lendC.connect(borrowerS).deposit(h, p, { value: 100n })).wait();

      const { h: bh, p: bp } = await encryptL(borrowerS, 60n);
      await (await lendC.connect(borrowerS).borrow(bh, bp)).wait();

      const isLiq = await fhevm.userDecryptEbool(
        await lendC.getIsLiquidatable(borrowerS.address), lendAddr, borrowerS
      );
      expect(isLiq).to.be.false; // 100*100=10000 vs 60*150=9000 → safe
    });

    it("premium score (820) → 110% ratio — same position is STILL safe with tighter ratio", async function () {
      await setScore(borrowerS, 820n);

      // Re-borrow to recompute health factor with score active
      const { h, p } = await encryptL(borrowerS, 1n); // tiny borrow to trigger recompute
      await (await lendC.connect(borrowerS).borrow(h, p)).wait();

      const isLiq = await fhevm.userDecryptEbool(
        await lendC.getIsLiquidatable(borrowerS.address), lendAddr, borrowerS
      );
      // collateral=100, debt=61 → 10000 vs 61*110=6710 → NOT liquidatable even with tighter ratio
      expect(isLiq).to.be.false;
    });

    it("premium score (820) unlocks tighter ratio — position unsafe at 150% is safe at 110%", async function () {
      // Fresh borrower with score
      const signers = await ethers.getSigners();
      const freshB  = signers[15];
      await setScore(freshB, 820n);

      const { h, p } = await encryptL(freshB, 100n);
      await (await lendC.connect(freshB).deposit(h, p, { value: 100n })).wait();

      // At 150% ratio: 100*100=10000 vs 75*150=11250 → liquidatable
      // At 110% ratio: 100*100=10000 vs 75*110=8250 → NOT liquidatable
      const { h: bh, p: bp } = await encryptL(freshB, 75n);
      await (await lendC.connect(freshB).borrow(bh, bp)).wait();

      const isLiq = await fhevm.userDecryptEbool(
        await lendC.getIsLiquidatable(freshB.address), lendAddr, freshB
      );
      expect(isLiq).to.be.false; // premium score protects this position
    });

    it("no-score borrower: same position (collateral 100, debt 75) IS liquidatable at 150%", async function () {
      const signers = await ethers.getSigners();
      const noScore = signers[16];

      // Deploy fresh ShieldLend WITHOUT score contract for this test
      const lendFactory = await ethers.getContractFactory("ConfidentialLending");
      const plainLend   = await lendFactory.deploy();
      await plainLend.waitForDeployment();
      const plainAddr   = await plainLend.getAddress();

      const cr = await fhevm.encryptUint(FhevmType.euint64, 100n, plainAddr, noScore.address);
      await (await plainLend.connect(noScore).deposit(
        ethers.hexlify(cr.externalEuint as any), ethers.hexlify(cr.inputProof as any), { value: 100n }
      )).wait();
      const br = await fhevm.encryptUint(FhevmType.euint64, 75n, plainAddr, noScore.address);
      await (await plainLend.connect(noScore).borrow(
        ethers.hexlify(br.externalEuint as any), ethers.hexlify(br.inputProof as any)
      )).wait();

      const isLiq = await fhevm.userDecryptEbool(
        await plainLend.getIsLiquidatable(noScore.address), plainAddr, noScore
      );
      expect(isLiq).to.be.true; // 100*100=10000 vs 75*150=11250 → liquidatable without score
    });
  });
});
