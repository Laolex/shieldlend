/**
 * Resume deployment — MockZAMA and ShieldScore already deployed.
 * Only deploys ConfidentialLending, wires ShieldScore, registers tokens.
 */
import { ethers } from "hardhat";

const MOCK_ZAMA    = "0x0737E6c3dCBD76973730CC50031074AF50914308";
const SCORE_ADDR   = "0x4d51e934d16f72b7fed83E3BB46cc813A0E5EAE5";
const USDC_SEPOLIA = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

const ETH_WEI   = 10n ** 18n;
const USDC_PRICE = ETH_WEI / 3000n;
const ZAMA_PRICE = ETH_WEI / 100n;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH\n");
  console.log("Reusing MockZAMA:            ", MOCK_ZAMA);
  console.log("Reusing ConfidentialCreditScore:", SCORE_ADDR, "\n");

  console.log("Deploying ConfidentialLending...");
  const LendingFactory = await ethers.getContractFactory("ConfidentialLending");
  const lendingContract = await LendingFactory.deploy();
  await lendingContract.waitForDeployment();
  const lendingAddr = await lendingContract.getAddress();
  console.log("ConfidentialLending:", lendingAddr);
  console.log("  Etherscan:", `https://sepolia.etherscan.io/address/${lendingAddr}\n`);

  console.log("Wiring ShieldScore...");
  let tx = await lendingContract.setScoreContract(SCORE_ADDR);
  await tx.wait();
  console.log("Done.\n");

  console.log("Adding USDC as collateral token...");
  tx = await lendingContract.addToken(USDC_SEPOLIA, 6, USDC_PRICE);
  await tx.wait();
  console.log(`  USDC ${USDC_SEPOLIA}\n`);

  console.log("Adding MockZAMA as collateral token...");
  tx = await lendingContract.addToken(MOCK_ZAMA, 18, ZAMA_PRICE);
  await tx.wait();
  console.log(`  ZAMA ${MOCK_ZAMA}\n`);

  console.log("=== Deployment Summary ===");
  console.log(`ConfidentialLending:     ${lendingAddr}`);
  console.log(`ConfidentialCreditScore: ${SCORE_ADDR}`);
  console.log(`MockZAMA:                ${MOCK_ZAMA}`);
  console.log(`USDC (Sepolia):          ${USDC_SEPOLIA}`);
  console.log("\nUpdate frontend/src/config.ts:");
  console.log(`  CONTRACT_ADDRESS         = "${lendingAddr}"`);
  console.log(`  ZAMA_TOKEN_ADDRESS       = "${MOCK_ZAMA}"`);
  console.log("\nUpdate frontend/.env:");
  console.log(`  VITE_SCORE_CONTRACT_ADDRESS=${SCORE_ADDR}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
