import os
import tempfile

# Use an isolated SQLite DB for tests before importing the app.
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.gettempdir()}/ids_test.db"
os.environ["SECRET_KEY"] = "test-secret-key"

from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.db.init_db import init_db

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
init_db()
client = TestClient(app)


def login():
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_unauthorized_detection_request():
    response = client.post("/api/v1/detection/analyze", json={
        "src_ip": "192.168.1.50", "dst_ip": "10.0.0.5", "src_port": 5000, "dst_port": 80,
        "protocol": "TCP", "bytes_sent": 100, "bytes_received": 200, "packet_count": 10,
    })
    assert response.status_code == 401


def test_login_returns_real_jwt():
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    assert response.json()["access_token"] != "mock-ids-jwt-token-secret-12345"
    assert response.json()["user"]["role"] == "ADMIN"


def test_benign_traffic_detection():
    token = login()
    response = client.post("/api/v1/detection/analyze", json={
        "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 443,
        "protocol": "TCP", "bytes_sent": 1500, "bytes_received": 4000, "packet_count": 25,
    }, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["threat_detected"] is False


def test_smb_rule_detection():
    token = login()
    response = client.post("/api/v1/detection/analyze", json={
        "src_ip": "192.168.1.200", "dst_ip": "10.0.0.5", "src_port": 49152, "dst_port": 445,
        "protocol": "TCP", "bytes_sent": 50000, "bytes_received": 100000, "packet_count": 300,
    }, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_detected"] is True
    assert any("SMB" in a["alert_type"] for a in data["triggered_alerts"])


def test_ddos_rule_detection():
    token = login()
    response = client.post("/api/v1/detection/analyze", json={
        "src_ip": "192.168.1.201", "dst_ip": "10.0.0.5", "src_port": 51234, "dst_port": 80,
        "protocol": "UDP", "bytes_sent": 2000000, "bytes_received": 100, "packet_count": 1200,
    }, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_detected"] is True
    assert any(a["severity"] == "CRITICAL" for a in data["triggered_alerts"])


def test_alert_feed_contains_network_context():
    token = login()
    response = client.get("/api/v1/detection/alerts", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    if response.json():
        alert = response.json()[0]
        assert "src_ip" in alert
        assert "dst_ip" in alert
