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


def hdr():
    return {"Authorization": f"Bearer {login()}"}


def test_invalid_credentials_rejected():
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert r.status_code == 401


def test_invalid_token_rejected():
    r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401


def test_me_endpoint_returns_profile():
    r = client.get("/api/v1/auth/me", headers=hdr())
    assert r.status_code == 200 and r.json()["username"] == "admin"


def test_rbac_analyst_forbidden_from_admin_route():
    tok = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"}).json()["access_token"]
    assert client.get("/api/v1/auth/admin-only", headers={"Authorization": f"Bearer {tok}"}).status_code == 403
    assert client.get("/api/v1/auth/admin-only", headers=hdr()).status_code == 200


def test_register_and_duplicate_rejected():
    body = {"username": "newuser1", "email": "newuser1@x.io", "password": "secret123"}
    assert client.post("/api/v1/auth/register", json=body).status_code == 201
    assert client.post("/api/v1/auth/register", json=body).status_code == 400


def test_invalid_payload_validation():
    bad = {"src_ip": "not-an-ip", "dst_ip": "10.0.0.5", "src_port": 70000, "dst_port": 80, "protocol": "TCP", "bytes_sent": -5, "bytes_received": 1, "packet_count": 0}
    assert client.post("/api/v1/detection/analyze", json=bad, headers=hdr()).status_code == 422


def test_port_scan_detected_end_to_end():
    r = client.post("/api/v1/detection/analyze", json={"src_ip": "203.0.113.9", "dst_ip": "10.0.0.5", "src_port": 40000, "dst_port": 8081,
                    "protocol": "TCP", "bytes_sent": 600 * 52, "bytes_received": 0, "packet_count": 600}, headers=hdr())
    assert r.status_code == 200 and any("Port Scan" in a["alert_type"] for a in r.json()["triggered_alerts"])


def test_exfiltration_detected_end_to_end():
    r = client.post("/api/v1/detection/analyze", json={"src_ip": "192.168.1.77", "dst_ip": "198.51.100.4", "src_port": 40001, "dst_port": 443,
                    "protocol": "TCP", "bytes_sent": 8_000_000, "bytes_received": 300, "packet_count": 700}, headers=hdr())
    assert any("Exfiltration" in a["alert_type"] for a in r.json()["triggered_alerts"])


def test_alert_persisted_and_returned_in_feed():
    client.post("/api/v1/detection/analyze", json={"src_ip": "192.168.1.250", "dst_ip": "10.0.0.5", "src_port": 40002, "dst_port": 3389,
                "protocol": "TCP", "bytes_sent": 900, "bytes_received": 900, "packet_count": 8}, headers=hdr())
    feed = client.get("/api/v1/detection/alerts?limit=5", headers=hdr()).json()
    assert any(a["src_ip"] == "192.168.1.250" and a["dst_port"] == 3389 for a in feed)


def test_alert_limit_param_validated():
    assert client.get("/api/v1/detection/alerts?limit=0", headers=hdr()).status_code == 422
