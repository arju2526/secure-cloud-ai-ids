"""Unit tests for the rule engine, ML engine and hybrid engine (no HTTP layer)."""
from types import SimpleNamespace
import pytest
from app.models.entities import AlertSeverity
from app.services.rule_engine import evaluate_network_rules
from app.services.ml_engine import ml_detector
from app.services.detection_engine import analyze_log
from app.ml.dataset import generate
from app.ml.features import extract_features, FEATURE_NAMES


def flow(**kw):
    base = dict(src_ip="192.168.1.5", dst_ip="10.0.0.5", src_port=50000, dst_port=443, protocol="TCP",
                bytes_sent=1500, bytes_received=4000, packet_count=25)
    base.update(kw)
    return SimpleNamespace(**base)


def types(alerts):
    return [a["alert_type"] for a in alerts]


# ---------- rules ----------
def test_rule_ddos_by_packet_count():
    assert any("DDoS" in t for t in types(evaluate_network_rules(flow(packet_count=1500, bytes_sent=900000))))

def test_rule_ddos_by_bytes():
    assert any("DDoS" in t for t in types(evaluate_network_rules(flow(bytes_sent=10_000_001, packet_count=900))))

def test_rule_exfiltration():
    r = evaluate_network_rules(flow(bytes_sent=6_000_000, bytes_received=200, packet_count=500))
    assert any("Exfiltration" in t for t in types(r))

def test_rule_exfiltration_not_triggered_with_large_response():
    assert not any("Exfiltration" in t for t in types(evaluate_network_rules(flow(bytes_sent=6_000_000, bytes_received=50_000, packet_count=500))))

@pytest.mark.parametrize("port", [21, 22, 23, 445, 1433, 3306, 3389])
def test_rule_suspicious_ports(port):
    assert any("Suspicious Service" in t for t in types(evaluate_network_rules(flow(dst_port=port))))

def test_rule_port_scan_regression_after_fix():
    # 600 packets of 52 bytes: realistic SYN-scan flow. Original rule (bytes_sent < 2000) could never match this.
    assert any("Port Scan" in t for t in types(evaluate_network_rules(flow(packet_count=600, bytes_sent=600 * 52, bytes_received=0, dst_port=8081))))

def test_rule_port_scan_not_triggered_for_normal_bulk_transfer():
    assert not any("Port Scan" in t for t in types(evaluate_network_rules(flow(packet_count=600, bytes_sent=600 * 900))))

def test_rule_clean_flow_has_no_alert():
    assert evaluate_network_rules(flow()) == []

def test_rule_severity_mapping():
    smb = evaluate_network_rules(flow(dst_port=445))[0]
    ftp = evaluate_network_rules(flow(dst_port=21))[0]
    assert smb["severity"] == AlertSeverity.HIGH and ftp["severity"] == AlertSeverity.MEDIUM


# ---------- features ----------
def test_feature_vector_shape_and_finite():
    import numpy as np
    v = extract_features(0, 0, 0, 0)  # zero edge case must not produce NaN/inf
    assert v.shape == (len(FEATURE_NAMES),) and np.isfinite(v).all()


# ---------- ML ----------
def test_ml_artifacts_loaded():
    assert ml_detector.model is not None and ml_detector.scaler is not None and 0.3 < ml_detector.threshold < 0.95

@pytest.mark.parametrize("port", [80, 443, 53, 8080])
def test_ml_regression_benign_web_ports_not_flagged(port):
    # v1 defect: raw dst_port feature made benign HTTPS (443) an "anomaly" (score 0.548 > threshold)
    assert ml_detector.predict(flow(dst_port=port)) is None

def test_ml_flags_volumetric_outlier():
    r = ml_detector.predict(flow(bytes_sent=40_000_000, bytes_received=100, packet_count=30000, dst_port=80))
    assert r is not None and r["severity"] in (AlertSeverity.HIGH, AlertSeverity.CRITICAL, AlertSeverity.MEDIUM)
    assert 0 < r["confidence_score"] <= 0.99

def test_ml_score_is_deterministic():
    a = ml_detector.score(1500, 4000, 25, 443); b = ml_detector.score(1500, 4000, 25, 443)
    assert a == b

def test_ml_false_positive_rate_on_benign_below_8_percent():
    recs = generate(1500, 0, seed=9001, include_attacks=False)
    fp = sum(ml_detector.predict(SimpleNamespace(**r)) is not None for r in recs)
    assert fp / len(recs) < 0.08


# ---------- hybrid ----------
def test_hybrid_deduplicates_and_combines():
    res = analyze_log(flow(packet_count=5000, bytes_sent=4_000_000, dst_port=80))
    ts = types(res)
    assert any("DDoS" in t for t in ts) and len(ts) == len(set((a["alert_type"], a["summary"]) for a in res))

def test_hybrid_benign_flow_clean():
    assert analyze_log(flow()) == []
