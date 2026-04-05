/**
 * Wire already-deployed contracts — no new deployments.
 */
import { ethers } from "hardhat";

const LENDING_ADDR = "0x8b28B283Fc19A747B2fB69BA4428541a4b8bEafB";
const SCORE_ADDR   = "0x4d51e934d16f72b7fed83E3BB46cc813A0E5EAE5";
const MOCK_ZAMA    = "0x0737E6c3dCBD76973730CC50031074AF50914308";
const USDC_SEPOLIA = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

const ETH_WEI    = 10n ** 18n;
const USDC_PRICE = ETH_WEI / 3000n;
const ZAMA_PRICE = ETH_WEI / 100n;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH\n");

  const lending = await ethers.getContractAt("ConfidentialLending", LENDING_ADDR);

  console.log("Wiring ShieldScore...");
  let tx = await lending.setScoreContract(SCORE_ADDR);
  await tx.wait();
  console.log("Done.\n");

  console.log("Adding USDC...");
  tx = await lending.addToken(USDC_SEPOLIA, 6, USDC_PRICE);
  await tx.wait();
  console.log(`  USDC ${USDC_SEPOLIA}\n`);

  console.log("Adding MockZAMA...");
  tx = await lending.addToken(MOCK_ZAMA, 18, ZAMA_PRICE);
  await tx.wait();
  console.log(`  ZAMA ${MOCK_ZAMA}\n`);

  console.log("=== All done ===");
  console.log(`ConfidentialLending:     ${LENDING_ADDR}`);
  console.log(`ConfidentialCreditScore: ${SCORE_ADDR}`);
  console.log(`MockZAMA:                ${MOCK_ZAMA}`);
  console.log(`USDC (Sepolia):          ${USDC_SEPOLIA}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
