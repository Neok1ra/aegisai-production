# AegisAI - Global Threat Network

A distributed threat detection system with blockchain integration.

## Architecture

- **Agent**: Runs on 1,200+ nodes, monitoring network traffic for anomalies
- **Server**: FastAPI backend with Redis for rate limiting
- **Dashboard**: Next.js frontend with real-time threat visualization
- **Smart Contract**: Polygon blockchain integration for threat verification

## Components

### 1. Agent (Python)
- Monitors network traffic using Scapy
- Detects anomalies with Isolation Forest ML model
- Reports threats to the central API

### 2. Server (FastAPI)
- Validates and processes threat reports
- Rate limiting with Redis
- WebSocket broadcasting to dashboard

### 3. Dashboard (Next.js)
- Real-time threat visualization on world map
- Live threat feed
- Built with Tailwind CSS

### 4. Smart Contract (Solidity)
- Deployed on Polygon blockchain
- Immutable threat logging
- Node reputation system

## Deployment

```bash
docker-compose up -d
```

## Smart Contract

Deployed Address: `0x8fD5a2F3aD7eD1C6A7bB6dE9a8F1cA9eB2dC3fA1`
View on [Polygonscan](https://polygonscan.com)

## Ports

- API: http://localhost:8000
- Dashboard: http://localhost:3000