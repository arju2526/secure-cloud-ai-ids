"""Train the v2 Isolation Forest on BENIGN-only synthetic flows (unsupervised) and calibrate the alert threshold.

Seeds: train=11 (fit), validation=22 (threshold calibration, benign only). Evaluation uses different seeds (scripts/evaluate.py).
Threshold = 95th percentile of anomaly scores on held-out benign validation flows (operating point chosen from a percentile sweep 90/95/97/99 on tuning seed 33; 95 gives ~3.6% benign alert rate with usable recall).
"""
import json
import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.ml.dataset import generate
from app.ml.features import feature_matrix, FEATURE_NAMES

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")


def train_and_save_model(n_train=5000, n_val=2000, percentile=95.0):
    train = generate(n_train, 0, seed=11, include_attacks=False)
    val = generate(n_val, 0, seed=22, include_attacks=False)
    scaler = StandardScaler().fit(feature_matrix(train))
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(scaler.transform(feature_matrix(train)))
    val_scores = -model.score_samples(scaler.transform(feature_matrix(val)))
    threshold = float(np.percentile(val_scores, percentile))
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    meta = {"version": "v2", "features": FEATURE_NAMES, "n_train_benign": n_train, "n_val_benign": n_val,
            "threshold_percentile": percentile, "threshold": threshold, "n_estimators": 200}
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved v2 model. threshold={threshold:.4f}")
    return meta


if __name__ == "__main__":
    train_and_save_model()
