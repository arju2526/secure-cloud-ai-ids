import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

def train_and_save_model():
    # 1. Synthetic baseline normal traffic distributions: [bytes_sent, bytes_received, packet_count, dst_port]
    np.random.seed(42)
    normal_traffic = np.random.normal(loc=[1500, 3500, 20, 80], scale=[500, 1000, 10, 20], size=(1000, 4))
    
    # Clip negative values
    normal_traffic = np.clip(normal_traffic, a_min=0, a_max=None)

    # 2. Fit Scaler
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(normal_traffic)

    # 3. Train Isolation Forest (Contamination = 5% baseline outlier rate)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(scaled_data)

    # 4. Save artifacts
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"ML Model successfully saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_and_save_model()
