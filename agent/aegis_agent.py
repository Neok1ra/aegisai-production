import asyncio
import aiohttp
import hashlib
import time
import logging
import numpy as np
try:
    from scapy.all import AsyncSniff
except ImportError:
    AsyncSniff = None
try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None
try:
    import joblib
except ImportError:
    joblib = None
try:
    import jwt
except ImportError:
    jwt = None
try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None
import os
import requests

# === CONFIG ===
API_URL = os.getenv("API_URL", "http://server:8000/v1/threat")
JWT_SECRET = os.getenv("JWT_SECRET")
NODE_ID = "node-" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
MODEL_PATH = "/models/anomaly_v3.pkl"
PINATA_JWT = os.getenv("PINATA_JWT")
SENTRY_DSN = os.getenv("SENTRY_DSN")

if SENTRY_DSN and sentry_sdk:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=1.0)

logging.basicConfig(level=logging.INFO)

# Load model
model = None
if joblib:
    try:
        model = joblib.load(MODEL_PATH)
    except:
        pass

# Fallback model if loading failed or joblib not available
if not model and IsolationForest:
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(np.random.rand(100, 5))

async def submit_threat(threat_data: dict):
    if not jwt:
        logging.error("JWT library not available")
        return
        
    payload = jwt.encode({"node_id": NODE_ID, "exp": int(time.time()) + 60}, JWT_SECRET, algorithm="HS256")
    headers = {"Authorization": f"Bearer {payload}"}

    async with aiohttp.ClientSession() as session:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.post(API_URL, json=threat_data, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    logging.info(f"THREAT: {threat_data['hash'][:8]}... | {threat_data['type']}")
                    await pin_to_ipfs(threat_data)
        except Exception as e:
            logging.error(f"Submit failed: {e}")
            if sentry_sdk:
                sentry_sdk.capture_exception(e)

async def pin_to_ipfs(threat: dict):
    if not PINATA_JWT: return
    url = "https://api.pinata.cloud/pinning/pinJSONToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}", "Content-Type": "application/json"}
    payload = {"pinataContent": threat, "pinataMetadata": {"name": f"threat-{threat['hash'][:8]}"}}
    try:
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code == 200:
            logging.info(f"IPFS: {r.json()['IpfsHash']}")
    except: pass

def extract_features(pkt):
    try:
        if pkt.haslayer('IP'):
            ip = pkt['IP']
            return np.array([len(pkt), ip.ttl, ip.proto, getattr(ip, 'sport', 0) or 0, getattr(ip, 'dport', 0) or 0])
    except: pass
    return None

async def monitor():
    if not AsyncSniff:
        logging.error("Scapy AsyncSniff not available")
        return
        
    def cb(pkt):
        if not model:
            return
            
        feats = extract_features(pkt)
        if feats is not None:
            try:
                score = model.score_samples([feats])[0]
                if score < -0.78:
                    h = hashlib.sha256(str(pkt).encode()).hexdigest()
                    threat_type = "port_scan" if 'TCP' in pkt and pkt['TCP'].flags == 2 else "anomaly"
                    threat = {
                        "hash": h,
                        "type": threat_type,
                        "confidence": min(99, int(-score * 120)),
                        "source_ip": pkt['IP'].src if 'IP' in pkt else None,
                        "dest_ip": pkt['IP'].dst if 'IP' in pkt else None,
                        "timestamp": int(time.time()),
                        "node_id": NODE_ID
                    }
                    asyncio.create_task(submit_threat(threat))
            except Exception as e:
                logging.error(f"Error processing packet: {e}")

    logging.info(f"Agent STARTED | {NODE_ID}")
    sniff = AsyncSniff(prn=cb, filter="tcp or udp or icmp", store=False)
    sniff.start()
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(monitor())