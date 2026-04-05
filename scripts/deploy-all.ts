import { ethers } from "hardhat";

/**
 * Deploy all ShieldLend contracts and wire them together.
 *
 * Order:
 *  1. MockZAMA (testnet ZAMA token with faucet)
 *  2. ConfidentialCreditScore (ShieldScore module)
 *  3. ConfidentialLending
 *  4. Wire: lending.setScoreContract(scoreAddr)
 *  5. Register collateral tokens: USDC (Sepolia) + MockZAMA
 *
 * Token prices (hardcoded for hackathon):
 *   USDC:  3000 USDC/ETH  → ethWeiPerToken = 1e18/3000 = 333333333333333
 *   ZAMA:   100 ZAMA/ETH  → ethWeiPerToken = 1e18/100  = 10000000000000000
 */

// Circle's official USDC on Sepolia
const USDC_SEPOLIA = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

// Price helpers
const ETH_WEI = 10n ** 18n;
const USDC_PRICE = ETH_WEI / 3000n;   // 1 USDC = 1/3000 ETH
const ZAMA_PRICE = ETH_WEI / 100n;    // 1 ZAMA = 1/100 ETH = 0.01 ETH

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH\n");

  // 1 — Deploy MockZAMA
  console.log("Deploying MockZAMA...");
  const ZamaFactory = await ethers.getContractFactory("MockZAMA");
  const zamaToken = await ZamaFactory.deploy();
  await zamaToken.waitForDeployment();
  const zamaAddr = await zamaToken.getAddress();
  console.log("MockZAMA:", zamaAddr);
  console.log("  Etherscan:", `https://sepolia.etherscan.io/address/${zamaAddr}\n`);

  // 2 — Deploy ShieldScore
  console.log("Deploying ConfidentialCreditScore...");
  const ScoreFactory = await ethers.getContractFactory("ConfidentialCreditScore");
  const scoreContract = await ScoreFactory.deploy();
  await scoreContract.waitForDeployment();
  const scoreAddr = await scoreContract.getAddress();
  console.log("ConfidentialCreditScore:", scoreAddr);
  console.log("  Etherscan:", `https://sepolia.etherscan.io/address/${scoreAddr}\n`);

  // 3 — Deploy ConfidentialLending
  console.log("Deploying ConfidentialLending...");
  const LendingFactory = await ethers.getContractFactory("ConfidentialLending");
  const lendingContract = await LendingFactory.deploy();
  await lendingContract.waitForDeployment();
  const lendingAddr = await lendingContract.getAddress();
  console.log("ConfidentialLending:", lendingAddr);
  console.log("  Etherscan:", `https://sepolia.etherscan.io/address/${lendingAddr}\n`);

  // 4 — Wire ShieldScore
  console.log("Wiring ShieldScore...");
  let tx = await lendingContract.setScoreContract(scoreAddr);
  await tx.wait();
  console.log("Done.\n");

  // 5 — Register USDC
  console.log("Adding USDC as collateral token...");
  tx = await lendingContract.addToken(USDC_SEPOLIA, 6, USDC_PRICE);
  await tx.wait();
  console.log(`  USDC ${USDC_SEPOLIA} — price: ${USDC_PRICE} wei/token (3000 USDC/ETH)\n`);

  // 6 — Register MockZAMA
  console.log("Adding MockZAMA as collateral token...");
  tx = await lendingContract.addToken(zamaAddr, 18, ZAMA_PRICE);
  await tx.wait();
  console.log(`  ZAMA ${zamaAddr} — price: ${ZAMA_PRICE} wei/token (100 ZAMA/ETH)\n`);

  console.log("=== Deployment Summary ===");
  console.log(`ConfidentialLending:     ${lendingAddr}`);
  console.log(`ConfidentialCreditScore: ${scoreAddr}`);
  console.log(`MockZAMA:                ${zamaAddr}`);
  console.log(`USDC (Sepolia):          ${USDC_SEPOLIA}`);
  console.log("\nUpdate frontend/src/config.ts:");
  console.log(`  CONTRACT_ADDRESS         = "${lendingAddr}"`);
  console.log(`  ZAMA_TOKEN_ADDRESS       = "${zamaAddr}"`);
  console.log("\nUpdate frontend/.env:");
  console.log(`  VITE_SCORE_CONTRACT_ADDRESS=${scoreAddr}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
