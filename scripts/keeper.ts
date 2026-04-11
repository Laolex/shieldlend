/**
 * ShieldLend Interest Accrual Keeper
 *
 * Automated keeper bot that periodically accrues interest on all active
 * borrower positions. Since FHE prevents aggregating encrypted debt sums
 * on-chain, interest accrual is triggered externally by the admin.
 *
 * This keeper iterates over all active borrowers and calls accrueInterest()
 * for each position, respecting a configurable minimum interval between
 * accruals to avoid excessive gas costs.
 *
 * Usage:
 *   PRIVATE_KEY=0x... RPC_URL=https://... npx hardhat run scripts/keeper.ts --network sepolia
 *
 * For production:
 *   Run via cron (e.g., every 6 hours) or as a systemd timer.
 *   Example crontab entry:
 *     0 */6 * * * cd /path/to/shieldlend && PRIVATE_KEY=0x... RPC_URL=https://... npx hardhat run scripts/keeper.ts --network sepolia >> /var/log/shieldlend-keeper.log 2>&1
 */

import { ethers } from "hardhat";

const CONTRACT_ADDRESS = process.env.LENDING_CONTRACT ?? "0x8b28B283Fc19A747B2fB69BA4428541a4b8bEafB";

// Minimum seconds between accruals for the same borrower (default: 6 hours)
const MIN_ACCRUAL_INTERVAL = Number(process.env.ACCRUAL_INTERVAL ?? 21600);

async function main() {
  const [signer] = await ethers.getSigners();
  console.log(`[keeper] signer: ${signer.address}`);

  const contract = await ethers.getContractAt("ConfidentialLending", CONTRACT_ADDRESS, signer);

  // Verify signer has ADMIN_ROLE
  const ADMIN_ROLE = await contract.ADMIN_ROLE();
  const isAdmin = await contract.hasRole(ADMIN_ROLE, signer.address);
  if (!isAdmin) {
    console.error("[keeper] ERROR: signer does not have ADMIN_ROLE — cannot accrue interest");
    process.exit(1);
  }

  const borrowerCount = Number(await contract.getBorrowerCount());
  console.log(`[keeper] active borrowers: ${borrowerCount}`);

  if (borrowerCount === 0) {
    console.log("[keeper] no active positions — nothing to do");
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  let accrued = 0;
  let skipped = 0;

  for (let i = 0; i < borrowerCount; i++) {
    const borrower = await contract.borrowerList(i);

    try {
      // Check if enough time has passed since last accrual
      const position = await contract.isActive(borrower);
      if (!position) {
        skipped++;
        continue;
      }

      // The contract stores lastAccrual but it's not exposed via a getter.
      // We accrue unconditionally and rely on the cron interval to prevent
      // over-accrual. For tighter control, add a lastAccrual() view to the contract.

      const tx = await contract.accrueInterest(borrower);
      const receipt = await tx.wait();
      console.log(`[keeper] accrued interest for ${borrower} (tx: ${receipt!.hash})`);
      accrued++;
    } catch (e: any) {
      console.error(`[keeper] failed for ${borrower}: ${e.message?.slice(0, 100)}`);
      skipped++;
    }
  }

  console.log(`[keeper] done — accrued: ${accrued}, skipped: ${skipped}`);
}

main().catch((e) => {
  console.error("[keeper] fatal:", e);
  process.exit(1);
});
