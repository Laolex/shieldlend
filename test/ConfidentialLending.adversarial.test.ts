/**
 * Adversarial test suite for ConfidentialLending v2
 * Tests FHE math correctness, protocol invariants, and new v2 features.
 *
 * 10 test cases as specified in the protocol upgrades design doc.
 */
import { ethers, fhevm } from "hardhat";
import { expect } from "chai";
import { ConfidentialLending } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { FhevmType } from "@fhevm/hardhat-plugin";

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function encU64(signer: HardhatEthersSigner, amount: bigint, addr: string) {
  const r = await fhevm.encryptUint(FhevmType.euint64, amount, addr, signer.address);
  return {
    externalEuint: ethers.hexlify(r.externalEuint as any),
    inputProof:    ethers.hexlify(r.inputProof as any),
  };
}

async function decU64(handle: bigint, addr: string, signer: HardhatEthersSigner): Promise<bigint> {
  return fhevm.userDecryptEuint(FhevmType.euint64, handle, addr, signer);
}

async function decBool(handle: bigint, addr: string, signer: HardhatEthersSigner): Promise<boolean> {
  return fhevm.userDecryptEbool(handle, addr, signer);
}

async function deployFresh(): Promise<[ConfidentialLending, string, HardhatEthersSigner[]]> {
  const signers = await ethers.getSigners();
  const factory = await ethers.getContractFactory("ConfidentialLending");
  const c = await factory.deploy() as ConfidentialLending;
  await c.waitForDeployment();
  const addr = await c.getAddress();
  return [c, addr, signers];
}

async function deposit(
  c: ConfidentialLending, addr: string,
  signer: HardhatEthersSigner, amount: bigint
) {
  const enc = await encU64(signer, amount, addr);
  await (await c.connect(signer).deposit(enc.externalEuint, enc.inputProof, { value: amount })).wait();
}

async function borrow(
  c: ConfidentialLending, addr: string,
  signer: HardhatEthersSigner, amount: bigint
) {
  const enc = await encU64(signer, amount, addr);
  await (await c.connect(signer).borrow(enc.externalEuint, enc.inputProof)).wait();
}

async function repay(
  c: ConfidentialLending, addr: string,
  signer: HardhatEthersSigner, amount: bigint
) {
  const enc = await encU64(signer, amount, addr);
  await (await c.connect(signer).repay(enc.externalEuint, enc.inputProof)).wait();
}

// ─── Suite ────────────────────────────────────────────────────────────────────

describe("ConfidentialLending — Adversarial", function () {

  // ── Test 1: near-threshold ────────────────────────────────────────────────
  it("1. near-threshold: position at exactly 150% ratio is NOT liquidatable", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // collateral=150, debt=100 → collateral*100 = 15000, debt*150 = 15000 → NOT liquidatable (lt, not lte)
    await deposit(c, addr, user, 150n);
    await borrow(c, addr, user, 100n);

    const isLiq = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiq).to.be.false;
  });

  it("1b. near-threshold: one-wei below threshold becomes liquidatable", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // collateral=149, debt=100 → collateral*100 = 14900, debt*150 = 15000 → liquidatable
    await deposit(c, addr, user, 149n);
    await borrow(c, addr, user, 100n);

    const isLiq = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiq).to.be.true;
  });

  // ── Test 2: overflow-boundary ────────────────────────────────────────────
  it("2. overflow-boundary: large collateral value does not silent-wrap", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // uint64.max = 18446744073709551615
    // Use a large but safe value that fits in uint64 without wrapping when multiplied
    // collateral * 100 must fit uint64 → max collateral ≈ 1.8e17
    const collateral = 1_000_000_000_000n; // 1e12 wei
    const debtSafe   = 100_000_000_000n;   // 1e11 wei — safe ratio (10x collateral vs 150%)

    await deposit(c, addr, user, collateral);
    await borrow(c, addr, user, debtSafe);

    const isLiq = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiq).to.be.false;
  });

  // ── Test 3: floor-at-zero exact ──────────────────────────────────────────
  it("3. floor-at-zero exact: repay == debt → totalDebt = 0, not underflow", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await deposit(c, addr, user, 10000n);
    await borrow(c, addr, user, 5000n);

    // Exact repayment
    await repay(c, addr, user, 5000n);

    const debtHandle = await c.getEncryptedTotalDebt(user.address);
    const debt = await decU64(debtHandle, addr, user);
    expect(debt).to.equal(0n);
  });

  // ── Test 4: floor-at-zero excess ─────────────────────────────────────────
  it("4. floor-at-zero excess: repay > debt → totalDebt = 0, not wrap", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await deposit(c, addr, user, 10000n);
    await borrow(c, addr, user, 5000n);

    // Overpayment: repay 9999 when debt is 5000 → should clamp to 0
    await repay(c, addr, user, 9999n);

    const debtHandle = await c.getEncryptedTotalDebt(user.address);
    const debt = await decU64(debtHandle, addr, user);
    expect(debt).to.equal(0n);
  });

  // ── Test 5: multi-collateral health ──────────────────────────────────────
  it("5. multi-collateral health: ETH + borrow; health correctly tracked", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // ETH collateral = 10000, debt = 5000 → healthy (10000 * 100 = 1M > 5000 * 150 = 750k)
    await deposit(c, addr, user, 10000n);
    await borrow(c, addr, user, 5000n);

    const isLiq = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiq).to.be.false;

    // Add more ETH collateral — still healthy
    const enc = await encU64(user, 5000n, addr);
    await (await c.connect(user).deposit(enc.externalEuint, enc.inputProof, { value: 5000n })).wait();

    const isLiqAfter = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiqAfter).to.be.false;
  });

  // ── Test 6: sequential-accrual ───────────────────────────────────────────
  it("6. sequential-accrual: 3 accruals → totalDebt grows monotonically", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await deposit(c, addr, user, 10000n);
    await borrow(c, addr, user, 5000n);

    const getDebt = async () => decU64(await c.getEncryptedTotalDebt(user.address), addr, user);

    const d0 = await getDebt(); // 5000
    // [M-1 fix] each accrual requires 1-day cooldown — advance time between calls
    await ethers.provider.send("evm_increaseTime", [86401]);
    await ethers.provider.send("evm_mine", []);
    await (await c.accrueInterest(user.address)).wait();
    const d1 = await getDebt();
    await ethers.provider.send("evm_increaseTime", [86401]);
    await ethers.provider.send("evm_mine", []);
    await (await c.accrueInterest(user.address)).wait();
    const d2 = await getDebt();
    await ethers.provider.send("evm_increaseTime", [86401]);
    await ethers.provider.send("evm_mine", []);
    await (await c.accrueInterest(user.address)).wait();
    const d3 = await getDebt();

    expect(d1).to.be.greaterThan(d0);
    expect(d2).to.be.greaterThan(d1);
    expect(d3).to.be.greaterThan(d2);

    // Verify math: 5000 * 500bps / 10000 = 250 interest per accrual
    expect(d1).to.equal(5250n);
    expect(d2).to.equal(5512n); // floor(5250 * 500 / 10000) = 262 → 5512
  });

  // ── Test 7: credit-score-tiers ───────────────────────────────────────────
  it("7. credit-score-tiers: score < 600 → 150% — collateral=149, debt=100 is liquidatable", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await deposit(c, addr, user, 149n);
    await borrow(c, addr, user, 100n);

    // No score — defaults to 150% ratio
    const isLiq = await decBool(await c.getIsLiquidatable(user.address), addr, user);
    expect(isLiq).to.be.true;
  });

  // ── Test 8: borrow-at-cap ─────────────────────────────────────────────────
  it("8. borrow-at-cap: collateral at maxBorrowPerPosition reverts one-wei-over", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // Set cap: max collateral per position = 1000 wei
    await c.setCaps(0n, 1000n);

    // Deposit exactly at cap
    await deposit(c, addr, user, 1000n);
    // Should succeed — borrow is within cap
    await borrow(c, addr, user, 100n);

    // Deploy a second fresh instance to test rejection
    const [c2, addr2, [, user2]] = await deployFresh();
    await c2.setCaps(0n, 999n); // cap at 999

    await deposit(c2, addr2, user2, 1000n); // deposit 1000

    // Borrow should revert because ethDeposited (1000) > maxBorrowPerPosition (999)
    const enc = await encU64(user2, 100n, addr2);
    await expect(
      c2.connect(user2).borrow(enc.externalEuint, enc.inputProof)
    ).to.be.revertedWith("Borrow cap: collateral exceeds position limit");
  });

  // ── Test 9: reserve-gate ─────────────────────────────────────────────────
  it("9. reserve-gate: borrow reverts when protocolReserve < minReserveRatio", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await deposit(c, addr, user, 10000n);

    // Enable reserve gate: require 5% of totalReserves in protocolReserve
    // totalReserves = 10000, so protocolReserve must be >= 500
    // protocolReserve starts at 0 → should block borrow
    await c.setReserveParams(200n, 500n); // 2% fee, 5% min ratio

    const enc = await encU64(user, 1000n, addr);
    await expect(
      c.connect(user).borrow(enc.externalEuint, enc.inputProof)
    ).to.be.revertedWith("Reserve too low");

    // Pre-fund the reserve and retry
    await c.replenishReserve({ value: 600n }); // 600 > 5% of 10000 = 500
    await (await c.connect(user).borrow(enc.externalEuint, enc.inputProof)).wait();
    expect(await c.isActive(user.address)).to.be.true;
  });

  // ── Test 10: permissionless-liquidate ────────────────────────────────────
  it("10. permissionless-liquidate: non-LIQUIDATOR_ROLE liquidates after confirm", async function () {
    const [c, addr, signers] = await deployFresh();
    const [admin, user, stranger] = signers;

    // Pre-fund reserve so bonus can be paid
    await c.replenishReserve({ value: ethers.parseEther("0.01") });

    // Create liquidatable position: collateral=100, debt=200
    await deposit(c, addr, user, 100n);
    await borrow(c, addr, user, 200n);

    // Confirm liquidatable via reveal flow
    await (await c.requestLiquidationReveal(user.address)).wait();
    const handle    = await c.getIsLiquidatable(user.address);
    const handleHex = ethers.hexlify(handle as any);
    const result    = await fhevm.publicDecrypt([handleHex]);
    await (await c.verifyLiquidationReveal(
      user.address, [handleHex], result.abiEncodedClearValues, result.decryptionProof
    )).wait();

    expect(await c.isConfirmedLiquidatable(user.address)).to.be.true;

    // stranger (non-LIQUIDATOR_ROLE) liquidates
    const strangerBalBefore = await ethers.provider.getBalance(stranger.address);
    const tx      = await c.connect(stranger).liquidate(user.address);
    const receipt = await tx.wait();
    const gas     = receipt!.gasUsed * receipt!.gasPrice;
    const strangerBalAfter = await ethers.provider.getBalance(stranger.address);

    // Position closed
    expect(await c.isActive(user.address)).to.be.false;
    expect(await c.isConfirmedLiquidatable(user.address)).to.be.false;

    // Stranger received ETH (collateral - fee + bonus)
    // ethReward=100, fee=2% of 100=2, liquidatorAmount=98, bonus=5% of 100=5
    // Expected: 98 + 5 = 103
    const received = strangerBalAfter - strangerBalBefore + gas;
    expect(received).to.equal(103n);
  });

  // ── Test 11: emergencyLiquidate ──────────────────────────────────────────
  it("11. emergencyLiquidate: admin can liquidate without confirm flag", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // Liquidatable position
    await deposit(c, addr, user, 100n);
    await borrow(c, addr, user, 200n);

    // No reveal performed — confirmedLiquidatable is false
    expect(await c.isConfirmedLiquidatable(user.address)).to.be.false;

    // Admin emergency-liquidates — must set treasury first (M-2 fix)
    const [,, treasury] = await ethers.getSigners();
    await (await c.setLiquidationTreasury(treasury.address)).wait();
    await (await c.emergencyLiquidate(user.address)).wait();

    expect(await c.isActive(user.address)).to.be.false;
  });

  // ── Test 12: token freeze ─────────────────────────────────────────────────
  it("12. freezeToken: addToken → freeze → frozen=true; unfreeze → frozen=false", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    const dummyToken = ethers.Wallet.createRandom().address;
    await c.addToken(dummyToken, 18, 1000n);

    // Initially not frozen
    const cfg0 = await c.tokenConfigs(dummyToken);
    expect(cfg0.frozen).to.be.false;

    // Freeze
    await c.freezeToken(dummyToken);
    const cfg1 = await c.tokenConfigs(dummyToken);
    expect(cfg1.frozen).to.be.true;

    // Attempt depositToken on frozen token — must revert
    const enc = await encU64(user, 1000n, addr);
    await expect(
      c.connect(user).depositToken(dummyToken, 1000n, enc.externalEuint, enc.inputProof)
    ).to.be.revertedWith("Token frozen");

    // Unfreeze restores state
    await c.unfreezeToken(dummyToken);
    const cfg2 = await c.tokenConfigs(dummyToken);
    expect(cfg2.frozen).to.be.false;

    // Non-admin cannot freeze
    await expect(
      c.connect(user).freezeToken(dummyToken)
    ).to.be.reverted;
  });

  // ── Test 13: supply-cap ───────────────────────────────────────────────────
  it("13. supply-cap: deposit beyond ethSupplyCap reverts", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    await c.setCaps(1000n, 0n); // supply cap at 1000 wei

    // Deposit exactly at cap — succeeds
    await deposit(c, addr, user, 1000n);

    // One more wei — should revert
    const [,, user2] = await ethers.getSigners();
    const enc = await encU64(user2, 1n, addr);
    await expect(
      c.connect(user2).deposit(enc.externalEuint, enc.inputProof, { value: 1n })
    ).to.be.revertedWith("Supply cap reached");
  });

  // ── Test 14: reserve-factor accumulates ───────────────────────────────────
  it("14. reserve-factor: protocolReserve accumulates from liquidation proceeds", async function () {
    const [c, addr, [admin, user, liquidator]] = await deployFresh();

    await c.grantLiquidatorRole(liquidator.address);

    // Liquidatable position
    await deposit(c, addr, user, 100n);
    await borrow(c, addr, user, 200n);

    // Run reveal
    await (await c.requestLiquidationReveal(user.address)).wait();
    const handle    = await c.getIsLiquidatable(user.address);
    const handleHex = ethers.hexlify(handle as any);
    const result    = await fhevm.publicDecrypt([handleHex]);
    await (await c.verifyLiquidationReveal(
      user.address, [handleHex], result.abiEncodedClearValues, result.decryptionProof
    )).wait();

    const reserveBefore = await c.protocolReserve();
    await (await c.connect(liquidator).liquidate(user.address)).wait();
    const reserveAfter = await c.protocolReserve();

    // reserveFactor = 2% of 100 = 2 wei accumulated
    expect(reserveAfter - reserveBefore).to.equal(2n);
  });

  // ── Test 15: configurable rate model ─────────────────────────────────────
  it("15. rate-model: setRateParams changes effectiveRate and new positions use it", async function () {
    const [c, addr, [admin, user]] = await deployFresh();

    // Default: 5% base, 0% utilization uplift → effective = 500 bps
    expect(await c.effectiveRateBps()).to.equal(500n);

    // Set 8% base rate, 50% utilization, 4% max uplift
    // effectiveRate = 800 + (5000 * 400 / 10000) = 800 + 200 = 1000 bps (10%)
    await c.setRateParams(800, 5000, 400);
    expect(await c.effectiveRateBps()).to.equal(1000n);

    // New depositor gets the updated rate
    await deposit(c, addr, user, 10000n);
    const rateHandle = await c.getEncryptedInterestRate(user.address);
    const rate = await decU64(rateHandle, addr, user);
    expect(rate).to.equal(1000n);
  });

  // ── Test 16: C-01 handle-pinning — close path ────────────────────────────
  // A borrower with nonzero debt tries to substitute another user's zero-debt
  // totalDebt ciphertext (with a valid KMS signature) into their verifyAndClose.
  // Before the fix, this would close the position without repaying.
  it("16. C-01 handle-pinning: verifyAndClose rejects a foreign totalDebt handle", async function () {
    const [c, addr, signers] = await deployFresh();
    const attacker = signers[1];
    const victim   = signers[2]; // legitimately debt-free user

    // Victim opens + requests close → their totalDebt(0) handle becomes publicly decryptable.
    await deposit(c, addr, victim, 5000n);
    await (await c.connect(victim).requestClosePosition()).wait();
    const victimHandle   = await c.getEncryptedTotalDebt(victim.address);
    const victimHandleHx = ethers.hexlify(victimHandle as any);
    const victimSig      = await fhevm.publicDecrypt([victimHandleHx]);

    // Attacker opens a position AND borrows (nonzero debt), then requests close.
    await deposit(c, addr, attacker, 10000n);
    await borrow(c, addr, attacker, 3000n);
    await (await c.connect(attacker).requestClosePosition()).wait();

    // Attacker submits the VICTIM'S handle + sig to their own verifyAndClose.
    // The sig is valid (victim's debt really is 0) but the handle does not match
    // the attacker's own totalDebt slot. Must revert with "Handle mismatch".
    await expect(
      c.connect(attacker).verifyAndClose(
        [victimHandleHx],
        victimSig.abiEncodedClearValues,
        victimSig.decryptionProof
      )
    ).to.be.revertedWith("Handle mismatch");

    // Attacker's position must remain active with debt untouched.
    expect(await c.isActive(attacker.address)).to.be.true;
    const debt = await decU64(await c.getEncryptedTotalDebt(attacker.address), addr, attacker);
    expect(debt).to.equal(3000n);
  });

  // ── Test 17: C-01 handle-pinning — liquidation path ──────────────────────
  // An attacker tries to flip confirmedLiquidatable on a HEALTHY borrower by
  // submitting a different underwater borrower's ebool(true) handle + sig.
  it("17. C-01 handle-pinning: verifyLiquidationReveal rejects a foreign ebool handle", async function () {
    const [c, addr, signers] = await deployFresh();
    const [admin] = signers;
    const safe     = signers[3]; // healthy borrower
    const unsafe   = signers[4]; // underwater borrower

    // Healthy: collateral 150 / debt 50 → safe at 150% ratio
    await deposit(c, addr, safe, 150n);
    await borrow(c, addr, safe, 50n);
    // Underwater: collateral 100 / debt 80 → liquidatable (10000 < 80*150=12000)
    await deposit(c, addr, unsafe, 100n);
    await borrow(c, addr, unsafe, 80n);

    // Kick reveal on the underwater borrower — their ebool(true) becomes publicly
    // decryptable with a valid KMS sig.
    await (await c.requestLiquidationReveal(unsafe.address)).wait();
    const unsafeHandle   = await c.getIsLiquidatable(unsafe.address);
    const unsafeHandleHx = ethers.hexlify(unsafeHandle as any);
    const unsafeSig      = await fhevm.publicDecrypt([unsafeHandleHx]);

    // Kick reveal on the safe borrower too — so pendingLiquidationReveal[safe]=true.
    await (await c.requestLiquidationReveal(safe.address)).wait();

    // Attacker submits UNSAFE borrower's (true) handle + sig against SAFE borrower.
    // Before the fix this would set confirmedLiquidatable[safe] = true.
    await expect(
      c.verifyLiquidationReveal(
        safe.address,
        [unsafeHandleHx],
        unsafeSig.abiEncodedClearValues,
        unsafeSig.decryptionProof
      )
    ).to.be.revertedWith("Handle mismatch");

    expect(await c.isConfirmedLiquidatable(safe.address)).to.be.false;
  });

  // ── Test 18: C-02 depositToken clamp ─────────────────────────────────────
  // A malicious user encrypts an ETH-equivalent greater than their deposit's
  // true value. The on-chain FHE.select must clamp it to the oracle-derived
  // plaintext cap, preventing artificially inflated collateral.
  it("18. C-02 clamp: over-reported depositToken ETH-equivalent is capped", async function () {
    const [c, addr, signers] = await deployFresh();
    const attacker = signers[1];

    // Deploy MockZAMA (18 decimals) and register it at 1 ZAMA = 0.01 ETH.
    const zamaFactory = await ethers.getContractFactory("MockZAMA");
    const zama = await zamaFactory.deploy();
    await zama.waitForDeployment();
    const zamaAddr = await zama.getAddress();

    const PRICE = (10n ** 18n) / 100n; // 0.01 ETH per ZAMA
    await c.addToken(zamaAddr, 18, PRICE);

    // Fund attacker with 1 ZAMA and approve the lending contract.
    await (await zama.mint(attacker.address, 10n ** 18n)).wait();
    await (await zama.connect(attacker).approve(addr, 10n ** 18n)).wait();

    // True value of 1 ZAMA at the registered price = 0.01 ETH = 10^16 wei.
    const TRUE_WEI      = 10n ** 16n;
    // Attacker attempts to credit themselves 1 ETH (10^18 wei) of collateral.
    const OVER_REPORTED = 10n ** 18n;

    const enc = await encU64(attacker, OVER_REPORTED, addr);
    await (await c.connect(attacker).depositToken(
      zamaAddr, 10n ** 18n, enc.externalEuint, enc.inputProof
    )).wait();

    // Decrypt the stored collateral — must equal the cap (TRUE_WEI), NOT the over-reported value.
    const collateral = await decU64(await c.getEncryptedCollateral(attacker.address), addr, attacker);
    expect(collateral).to.equal(TRUE_WEI);
  });
});
