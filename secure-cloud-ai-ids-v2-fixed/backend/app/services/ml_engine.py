import json
import os
from typing import Optional, Dict, Any
import joblib
from app.models.entities import AlertSeverity, NetworkLog
from app.ml.features import extract_features

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")


class MLAnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.threshold = 0.6
        self.load_artifacts()

    def load_artifacts(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
        if os.path.exists(META_PATH):
            with open(META_PATH) as f:
                self.threshold = json.load(f)["threshold"]

    def score(self, bytes_sent, bytes_received, packet_count, dst_port) -> Optional[float]:
        """Anomaly score; higher = more anomalous."""
        if not self.model or not self.scaler:
            return None
        x = self.scaler.transform(extract_features(bytes_sent, bytes_received, packet_count, dst_port).reshape(1, -1))
        return float(-self.model.score_samples(x)[0])

    def predict(self, log: NetworkLog) -> Optional[Dict[str, Any]]:
        s = self.score(log.bytes_sent, log.bytes_received, log.packet_count, log.dst_port)
        if s is None or s <= self.threshold:
            return None
        margin = s - self.threshold
        severity = AlertSeverity.CRITICAL if margin > 0.10 else AlertSeverity.HIGH if margin > 0.05 else AlertSeverity.MEDIUM
        return {
            "alert_type": "ML Zero-Day Anomaly Detected",
            "severity": severity,
            "confidence_score": min(round(s, 2), 0.99),
            "summary": f"Unsupervised Isolation Forest identified statistical behavioral anomaly (Anomaly Score: {s:.2f}, threshold {self.threshold:.2f}) from {log.src_ip}.",
        }


ml_detector = MLAnomalyDetector()
