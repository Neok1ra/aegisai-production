const hre = require("hardhat");

async function main() {
  const AegisAI = await hre.ethers.getContractFactory("AegisAI");
  const aegisAI = await AegisAI.deploy();

  await aegisAI.deployed();

  console.log("AegisAI deployed to:", aegisAI.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});