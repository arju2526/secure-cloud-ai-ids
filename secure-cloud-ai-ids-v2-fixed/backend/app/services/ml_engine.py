import os
import joblib
import numpy as np
from typing import Optional, Dict, Any
from app.models.entities import AlertSeverity, NetworkLog

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

class MLAnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_artifacts()

    def load_artifacts(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)

    def predict(self, log: NetworkLog) -> Optional[Dict[str, Any]]:
        if not self.model or not self.scaler:
            return None

        # Feature vector: [bytes_sent, bytes_received, packet_count, dst_port]
        features = np.array([[log.bytes_sent, log.bytes_received, log.packet_count, log.dst_port]])
        scaled_features = self.scaler.transform(features)

        # Isolation Forest prediction: 1 = normal, -1 = anomaly
        pred = self.model.predict(scaled_features)[0]
        anomaly_score = float(-self.model.score_samples(scaled_features)[0]) # Higher = more anomalous

        if pred == -1 or anomaly_score > 0.65:
            # Map score to severity
            if anomaly_score > 0.80:
                severity = AlertSeverity.CRITICAL
            elif anomaly_score > 0.70:
                severity = AlertSeverity.HIGH
            else:
                severity = AlertSeverity.MEDIUM

            confidence = min(round(anomaly_score, 2), 0.99)

            return {
                "alert_type": "ML Zero-Day Anomaly Detected",
                "severity": severity,
                "confidence_score": confidence,
                "summary": f"Unsupervised Isolation Forest identified statistical behavioral anomaly (Anomaly Score: {anomaly_score:.2f}) from {log.src_ip}."
            }
        return None

ml_detector = MLAnomalyDetector()
