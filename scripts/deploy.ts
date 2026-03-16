import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const factory = await ethers.getContractFactory("ConfidentialLending");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("ConfidentialLending deployed to:", address);
  console.log("Etherscan:", `https://sepolia.etherscan.io/address/${address}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
