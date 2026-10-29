"""Shared feature extraction for the v2 anomaly detector (used by training AND inference)."""
import numpy as np

WEB_DNS_PORTS = (80, 443, 53, 8080, 8443)
FEATURE_NAMES = [
    "log_bytes_sent", "log_bytes_received", "log_packet_count",
    "log_bytes_per_packet", "log_send_recv_ratio", "is_web_dns_port", "is_privileged_port",
]


def extract_features(bytes_sent, bytes_received, packet_count, dst_port) -> np.ndarray:
    bs, br = float(bytes_sent), float(bytes_received)
    pk = max(float(packet_count), 1.0)
    return np.array([
        np.log1p(bs),
        np.log1p(br),
        np.log1p(pk),
        np.log1p(bs / pk),
        np.log1p(bs) - np.log1p(br),
        1.0 if int(dst_port) in WEB_DNS_PORTS else 0.0,
        1.0 if int(dst_port) < 1024 else 0.0,
    ])


def feature_matrix(records) -> np.ndarray:
    return np.vstack([extract_features(r["bytes_sent"], r["bytes_received"], r["packet_count"], r["dst_port"]) for r in records])
