#!/bin/bash

# Deploy AegisAI Smart Contract to Polygon
# Prerequisites: Hardhat, Polygon RPC endpoint, Private key

echo "Deploying AegisAI.sol to Polygon..."

# Using Hardhat
cd ../contracts
npx hardhat compile
npx hardhat run deploy.js --network polygon

echo "Deployment complete!"