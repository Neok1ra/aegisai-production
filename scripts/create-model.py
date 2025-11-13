import joblib, numpy as np
from sklearn.ensemble import IsolationForest
import os
X = np.random.rand(1000, 5)
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(X)
os.makedirs("../agent/models", exist_ok=True)
joblib.dump(model, "../agent/models/anomaly_v3.pkl")
print("Model created")