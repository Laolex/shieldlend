# ShieldLend Hackathon Finish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring ShieldLend to hackathon submission quality: public decryption reveal, passing tests, Sepolia deploy, updated frontend, Vercel deployment.

**Architecture:** Add `requestLiquidationReveal` + `verifyLiquidationReveal` to the contract using the v0.11.1 FHE API (`FHE.makePubliclyDecryptable` + `FHE.checkSignatures`). Test with `fhevm.publicDecryptEbool` + `fhevm.publicDecrypt`. Export ABI, update frontend config with deployed address, add "Request Reveal" button for liquidators, deploy to Vercel.

**Tech Stack:** Solidity 0.8.27 · `@fhevm/solidity ^0.11.1` · `@fhevm/hardhat-plugin ^0.4.2` · Hardhat · React/Vite · ethers.js v6 · Vercel

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `contracts/ConfidentialLending.sol` | Modify | Add `requestLiquidationReveal`, `verifyLiquidationReveal`, `LiquidationAlertPublic` event |
| `test/ConfidentialLending.test.ts` | Modify | Add public decryption tests |
| `frontend/src/config.ts` | Modify | Update CONTRACT_ADDRESS after deploy |
| `frontend/src/abi.json` | Replace | Export from compiled artifacts |
| `frontend/src/App.tsx` | Modify | Add "Request Reveal" button + `LiquidationAlertPublic` listener |

---

## Task 1: Add Public Decryption to Contract

**Files:**
- Modify: `contracts/ConfidentialLending.sol`

- [ ] **Step 1: Add state, event, and new functions to ConfidentialLending.sol**

Open `contracts/ConfidentialLending.sol`. Add the following after the existing events block (around line 48):

```solidity
    event LiquidationRevealRequested(address indexed borrower, bytes32 isLiquidatableHandle, uint256 timestamp);
    event LiquidationAlertPublic(address indexed borrower, bool isLiquidatable, uint256 timestamp);
```

Add the following after the existing `mapping(address => Position) private positions;` storage:

```solidity
    mapping(address => bool) private pendingLiquidationReveal;
```

Add the following two functions before the `// ─── View functions ───` section (around line 248):

```solidity
    // ─────────────────────────── Public Decryption ─────────────────────────

    /**
     * @notice Mark a position's liquidation status for public decryption by the Zama relayer.
     *         Anyone can request a reveal — the result will be publicly broadcast via event.
     *         Marks the ebool as publicly decryptable, then the relayer decrypts off-chain
     *         and calls verifyLiquidationReveal with the proof.
     */
    function requestLiquidationReveal(address borrower) external {
        require(positions[borrower].active, "No active position");
        ebool liqFlag = positions[borrower].isLiquidatable;
        FHE.makePubliclyDecryptable(liqFlag);
        pendingLiquidationReveal[borrower] = true;
        emit LiquidationRevealRequested(borrower, FHE.toBytes32(liqFlag), block.timestamp);
    }

    /**
     * @notice Submit the Zama relayer's decryption result + proof for a pending liquidation reveal.
     *         Verifies the KMS signatures via FHE.checkSignatures, then broadcasts the plaintext result.
     * @param borrower              Address whose isLiquidatable was decrypted
     * @param handlesList           Array containing the ebool handle (bytes32) — must match what was emitted
     * @param abiEncodedCleartexts  ABI-encoded bool from relayer (abi.encode(bool))
     * @param decryptionProof       KMS signatures + metadata from relayer
     */
    function verifyLiquidationReveal(
        address borrower,
        bytes32[] calldata handlesList,
        bytes calldata abiEncodedCleartexts,
        bytes calldata decryptionProof
    ) external {
        require(pendingLiquidationReveal[borrower], "No pending reveal for this borrower");
        FHE.checkSignatures(handlesList, abiEncodedCleartexts, decryptionProof);
        bool isLiquidatable = abi.decode(abiEncodedCleartexts, (bool));
        delete pendingLiquidationReveal[borrower];
        emit LiquidationAlertPublic(borrower, isLiquidatable, block.timestamp);
    }

    /**
     * @notice Returns whether a liquidation reveal is pending for a given borrower.
     */
    function isPendingReveal(address borrower) external view returns (bool) {
        return pendingLiquidationReveal[borrower];
    }
```

- [ ] **Step 2: Compile and verify no errors**

```bash
cd /home/laolex/Projects/shieldlend
npx hardhat compile
```

Expected: `Compiled N Solidity files successfully` with no errors.
If there's a `FHE.makePubliclyDecryptable` error, verify `@fhevm/solidity` version with `cat node_modules/@fhevm/solidity/package.json | grep version`.

- [ ] **Step 3: Commit contract changes**

```bash
cd /home/laolex/Projects/shieldlend
git add contracts/ConfidentialLending.sol
git commit -m "feat: add requestLiquidationReveal and verifyLiquidationReveal with FHE.checkSignatures"
```

---

## Task 2: Update Tests

**Files:**
- Modify: `test/ConfidentialLending.test.ts`

- [ ] **Step 1: Add public decryption test block**

Append the following describe block at the end of the file, before the final closing `});` of the outer describe:

```typescript
  // ── Public Decryption (FHE.makePubliclyDecryptable) ──────────────────────
  describe("Public Decryption — Liquidation Reveal", function () {
    let freshBorrower: HardhatEthersSigner;
    let freshContract: ConfidentialLending;
    let freshAddress: string;

    before(async function () {
      // Deploy a fresh instance so state is clean
      const factory = await ethers.getContractFactory("ConfidentialLending");
      freshContract = await factory.deploy();
      await freshContract.waitForDeployment();
      freshAddress = await freshContract.getAddress();
      [,,,,,, freshBorrower] = await ethers.getSigners();
      await freshContract.grantLiquidatorRole(liquidator.address);
    });

    it("requestLiquidationReveal marks ebool as publicly decryptable and emits event", async function () {
      // Setup: deposit + borrow at safe ratio
      const { externalEuint: ce, inputProof: cp } = await encryptUint64(freshBorrower, 30000n, freshAddress);
      await (await freshContract.connect(freshBorrower).deposit(ce, cp, { value: 30000n })).wait();
      const { externalEuint: be, inputProof: bp } = await encryptUint64(freshBorrower, 5000n, freshAddress);
      await (await freshContract.connect(freshBorrower).borrow(be, bp)).wait();

      // Request reveal
      const tx = await freshContract.requestLiquidationReveal(freshBorrower.address);
      const receipt = await tx.wait();

      // Verify event emitted
      expect(receipt?.logs.length).to.be.gt(0);
      expect(await freshContract.isPendingReveal(freshBorrower.address)).to.be.true;
    });

    it("publicDecryptEbool returns false for healthy position", async function () {
      const handle = await freshContract.getIsLiquidatable(freshBorrower.address);
      const handleHex = ethers.hexlify(handle as any);
      const isLiq = await fhevm.publicDecryptEbool(handleHex);
      expect(isLiq).to.be.false;
    });

    it("verifyLiquidationReveal accepts relayer proof and emits LiquidationAlertPublic", async function () {
      const handle = await freshContract.getIsLiquidatable(freshBorrower.address);
      const handleHex = ethers.hexlify(handle as any);

      // Get full decryption proof from mock environment
      const result = await fhevm.publicDecrypt([handleHex]);
      const handlesList = [handleHex] as `0x${string}`[];

      const tx = await freshContract.verifyLiquidationReveal(
        freshBorrower.address,
        handlesList,
        result.abiEncodedClearValues,
        result.decryptionProof
      );
      const receipt = await tx.wait();

      // Pending flag cleared
      expect(await freshContract.isPendingReveal(freshBorrower.address)).to.be.false;

      // LiquidationAlertPublic event emitted
      const iface = freshContract.interface;
      const alertEvent = receipt?.logs
        .map(l => { try { return iface.parseLog(l); } catch { return null; } })
        .find(e => e?.name === "LiquidationAlertPublic");
      expect(alertEvent).to.not.be.undefined;
      expect(alertEvent!.args.isLiquidatable).to.be.false;
    });
  });
```

**Note:** The `encryptUint64` helper is already defined at the top of the test file but takes `(signer, amount)` and uses the module-level `contractAddress`. Add a local overload at the top of the new describe block if the address differs, or just pass `freshAddress` to a parameterized helper. The simplest fix: change the helper at the top of the file to accept an optional address:

```typescript
// Replace existing encryptUint64:
async function encryptUint64(signer: HardhatEthersSigner, amount: bigint, addr?: string) {
  const target = addr ?? contractAddress;
  const r = await fhevm.encryptUint(FhevmType.euint64, amount, target, signer.address);
  return {
    externalEuint: ethers.hexlify(r.externalEuint as any),
    inputProof: ethers.hexlify(r.inputProof as any),
  };
}
```

- [ ] **Step 2: Run all tests and verify passing**

```bash
cd /home/laolex/Projects/shieldlend
npx hardhat test
```

Expected output: all existing tests pass + 3 new tests in "Public Decryption" pass.
If `publicDecrypt` or `publicDecryptEbool` API issues arise, check: `fhevm.publicDecrypt` takes `(string | Uint8Array)[]`. Ensure the handle is hexlified: `ethers.hexlify(handle as any)`.

- [ ] **Step 3: Commit tests**

```bash
git add test/ConfidentialLending.test.ts
git commit -m "test: add public decryption tests for requestLiquidationReveal and verifyLiquidationReveal"
```

---

## Task 3: Export ABI to Frontend

**Files:**
- Replace: `frontend/src/abi.json`

- [ ] **Step 1: Copy the compiled ABI**

After `npx hardhat compile` (Task 1 Step 2), the ABI is at:
`artifacts/contracts/ConfidentialLending.sol/ConfidentialLending.json`

Extract just the ABI array:

```bash
cd /home/laolex/Projects/shieldlend
node -e "
const fs = require('fs');
const artifact = JSON.parse(fs.readFileSync('artifacts/contracts/ConfidentialLending.sol/ConfidentialLending.json'));
fs.writeFileSync('frontend/src/abi.json', JSON.stringify(artifact.abi, null, 2));
console.log('ABI exported:', artifact.abi.length, 'entries');
"
```

Expected: `ABI exported: N entries` where N is 20+.

- [ ] **Step 2: Verify abi.json contains the new functions**

```bash
grep -E "requestLiquidationReveal|verifyLiquidationReveal|LiquidationAlertPublic|isPendingReveal" /home/laolex/Projects/shieldlend/frontend/src/abi.json
```

Expected: 4 matches found.

- [ ] **Step 3: Commit ABI**

```bash
git add frontend/src/abi.json
git commit -m "chore: update frontend ABI with public decryption functions"
```

---

## Task 4: Add "Request Reveal" Button to Frontend

**Files:**
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Add handleRequestReveal function**

In `App.tsx`, add the following function after `handleLiquidate` (around line 265):

```typescript
  const handleRequestReveal = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.requestLiquidationReveal(addr);
      await tx.wait();
      showToast(`Reveal requested for ${addr.slice(0, 6)}… — Zama relayer will decrypt`, "info");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };
```

- [ ] **Step 2: Add button to liquidator panel**

Find the borrower list render in the liquidator section (around line 378). Replace the borrower item JSX so it has both "Request Reveal" and "Liquidate" buttons:

```tsx
// Replace the existing borrowers.map(addr => ...) block with:
borrowers.map(addr => (
  <div className="sl-borrower-item" key={addr}>
    <div>
      <div style={{ fontSize:12, fontFamily:"Space Mono,monospace", marginBottom:4 }}>{addr.slice(0,10)}…{addr.slice(-6)}</div>
      <span className="enc-tag">🔒 health factor encrypted</span>
    </div>
    <div style={{ display:"flex", gap:8 }}>
      <button className="sl-btn-ghost" onClick={() => handleRequestReveal(addr)} disabled={loading}
        title="Mark isLiquidatable for public decryption by Zama relayer">
        {loading ? <span className="sl-spinner" /> : "🔓 Request Reveal"}
      </button>
      <button className="sl-btn-danger" onClick={() => handleLiquidate(addr)} disabled={loading}>
        {loading ? <span className="sl-spinner" /> : "Liquidate"}
      </button>
    </div>
  </div>
))
```

- [ ] **Step 3: Commit frontend changes**

```bash
git add frontend/src/App.tsx
git commit -m "feat: add Request Reveal button to liquidator panel for public FHE decryption"
```

---

## Task 5: Deploy to Sepolia

- [ ] **Step 1: Set Hardhat vars (run these in terminal)**

```bash
cd /home/laolex/Projects/shieldlend
npx hardhat vars set MNEMONIC
# paste your 12-word mnemonic when prompted

npx hardhat vars set INFURA_API_KEY
# paste your Infura API key when prompted

npx hardhat vars set ETHERSCAN_API_KEY
# paste Etherscan API key when prompted
```

- [ ] **Step 2: Verify deployer has Sepolia ETH**

```bash
npx hardhat console --network sepolia
# In console:
# const [deployer] = await ethers.getSigners()
# ethers.formatEther(await ethers.provider.getBalance(deployer.address))
# Should show > 0.05 ETH
```

- [ ] **Step 3: Deploy contract**

```bash
npx hardhat run scripts/deploy.ts --network sepolia
```

Expected output:
```
Deploying with: 0xYourAddress
Balance: 0.XX ETH
ConfidentialLending deployed to: 0xNEWADDRESS
Etherscan: https://sepolia.etherscan.io/address/0xNEWADDRESS
```

**Note the deployed address — needed for Step 4.**

- [ ] **Step 4: Verify on Etherscan (Standard JSON Input)**

```bash
node -e "
const fs = require('fs');
const buildInfo = fs.readdirSync('artifacts/build-info').find(f => f.endsWith('.json'));
const bi = JSON.parse(fs.readFileSync('artifacts/build-info/' + buildInfo));
fs.writeFileSync('std_input.json', JSON.stringify(bi.input, null, 2));
console.log('Written std_input.json');
"
```

Go to `https://sepolia.etherscan.io/address/0xNEWADDRESS#code` → Verify & Publish → Solidity (Standard-Json-Input) → compiler `0.8.27` → optimization `800 runs` → EVM `cancun` → upload `std_input.json`.

---

## Task 6: Update Frontend Config and Deploy to Vercel

**Files:**
- Modify: `frontend/src/config.ts`

- [ ] **Step 1: Update contract address in config.ts**

Edit `frontend/src/config.ts`:

```typescript
// Replace the placeholder address with the actual deployed address from Task 5 Step 3
export const CONTRACT_ADDRESS = "0xNEWADDRESS_FROM_DEPLOY";
export const NETWORK_NAME = "Sepolia";
export const CHAIN_ID = 11155111;
```

- [ ] **Step 2: Build the frontend locally to verify**

```bash
cd /home/laolex/Projects/shieldlend/frontend
npm install
npm run build
```

Expected: `dist/` created with no errors.

- [ ] **Step 3: Deploy to Vercel**

```bash
cd /home/laolex/Projects/shieldlend/frontend
npx vercel --prod
```

If prompted for project name, use `shieldlend`. If already linked, it deploys automatically.
Expected: `Production: https://shieldlend.vercel.app ✓`

- [ ] **Step 4: Verify live deployment**

Open `https://shieldlend.vercel.app` → Connect wallet (Sepolia) → Should show "FHE online" status.
Test the full flow:
1. Deposit ETH collateral
2. Borrow (less than 66% of collateral)
3. "🔒 Decrypt Position" → should show plaintext values
4. As liquidator: "🔓 Request Reveal" on a position

- [ ] **Step 5: Final commit**

```bash
cd /home/laolex/Projects/shieldlend
git add frontend/src/config.ts
git commit -m "deploy: update contract address to Sepolia deployment 0xNEWADDRESS"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] FHE.requestDecryption pattern → `requestLiquidationReveal` + `verifyLiquidationReveal`
- [x] Tests for new functions
- [x] Deploy to Sepolia
- [x] Frontend updated with deployed address + new button
- [x] Vercel deployment

**Gaps / Notes:**
- `verifyLiquidationReveal` requires a relayer or off-chain actor to call it with proof — on testnet, Zama's relayer handles this automatically after `makePubliclyDecryptable`. For the demo video, show the `requestLiquidationReveal` tx + the emitted `LiquidationRevealRequested` event. The `LiquidationAlertPublic` event comes asynchronously from the relayer callback.
- If `fhevm.publicDecrypt` API isn't available in the hardhat plugin version, fall back to `fhevm.publicDecryptEbool` for just verifying the decrypted value (skip the `verifyLiquidationReveal` test or mark it `.skip()` on non-mock environments).
- The `encryptUint64` helper needs the optional `addr` param — modify it first before adding tests that use `freshAddress`.
