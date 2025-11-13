from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
import jwt
import redis
import uvicorn
import os
import requests
import logging
from pydantic import BaseModel
from typing import Optional

# Sentry import with error handling
try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None

app = FastAPI()
security = HTTPBearer()

# Redis connection with error handling
try:
    r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
    # Test connection
    r.ping()
except Exception as e:
    r = None
    logging.warning(f"Could not connect to Redis: {e}")

JWT_SECRET = os.getenv("JWT_SECRET")
SENTRY_DSN = os.getenv("SENTRY_DSN")
PINATA_JWT = os.getenv("PINATA_JWT")

# Initialize Sentry if available and DSN is provided
if SENTRY_DSN and sentry_sdk:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Threat(BaseModel):
    hash: str
    type: str
    confidence: int
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: int
    node_id: str

# WebSocket clients
clients = []

@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in clients:
            clients.remove(websocket)

def verify(auth=Depends(security)):
    if not jwt:
        raise HTTPException(401, "JWT library not available")
        
    try:
        payload = jwt.decode(auth.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload["node_id"]
    except jwt.exceptions.PyJWTError:
        raise HTTPException(401, "Invalid token")
    except Exception:
        raise HTTPException(401, "Invalid token")

@app.post("/v1/threat")
async def report(t: Threat, node: str = Depends(verify)):
    # Rate limiting (if Redis is available)
    if r:
        key = f"rate:{node}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 60)
        if int(r.get(key) or 0) > 50:
            raise HTTPException(429, "Rate limited")

    # Broadcast to all connected WebSocket clients
    for client in clients[:]:  # Create a copy to avoid modification during iteration
        try:
            await client.send_json(t.dict())
        except Exception:
            if client in clients:
                clients.remove(client)

    # Save to IPFS
    if PINATA_JWT:
        try:
            url = "https://api.pinata.cloud/pinning/pinJSONToIPFS"
            headers = {
                "Authorization": f"Bearer {PINATA_JWT}",
                "Content-Type": "application/json"
            }
            payload = {
                "pinataContent": t.dict(),
                "pinataMetadata": {"name": f"threat-{t.hash[:8]}"}
            }
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                logging.info(f"IPFS: {response.json()['IpfsHash']}")
        except Exception as e:
            if sentry_sdk:
                sentry_sdk.capture_exception(e)
            logging.error(f"IPFS pinning failed: {e}")

    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)