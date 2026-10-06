from typing import List, Dict, Any
from app.models.entities import AlertSeverity, NetworkLog

# Known risky/suspicious operational ports
SUSPICIOUS_PORTS = {
    21: "FTP Unencrypted Access",
    22: "SSH Brute-Force Target",
    23: "Telnet Insecure Channel",
    1433: "MSSQL Database Probe",
    3306: "MySQL Database Probe",
    3389: "RDP Remote Desktop Scan",
    445: "SMB / EternalBlue Target"
}

def evaluate_network_rules(log: NetworkLog) -> List[Dict[str, Any]]:
    triggered_rules = []

    # Rule 1: High-Volume DDoS / Packet Surge
    if log.packet_count > 1000 or log.bytes_sent > 10_000_000:
        triggered_rules.append({
            "alert_type": "DDoS / High Volume Traffic Surge",
            "severity": AlertSeverity.CRITICAL,
            "confidence_score": 0.95,
            "summary": f"Extreme packet count ({log.packet_count}) or payload size ({log.bytes_sent} bytes) from {log.src_ip} targeting port {log.dst_port}."
        })

    # Rule 2: Potential Data Exfiltration
    if log.bytes_sent > 5_000_000 and log.bytes_received < 1000:
        triggered_rules.append({
            "alert_type": "Data Exfiltration Anomaly",
            "severity": AlertSeverity.HIGH,
            "confidence_score": 0.88,
            "summary": f"Unusually large outbound data transfer ({log.bytes_sent} bytes) to destination {log.dst_ip} with minimal response."
        })

    # Rule 3: Suspicious Service/Port Probing
    if log.dst_port in SUSPICIOUS_PORTS:
        service_desc = SUSPICIOUS_PORTS[log.dst_port]
        severity = AlertSeverity.HIGH if log.dst_port in [23, 445, 3389] else AlertSeverity.MEDIUM
        triggered_rules.append({
            "alert_type": f"Suspicious Service Access ({service_desc})",
            "severity": severity,
            "confidence_score": 0.82,
            "summary": f"Traffic probe targeting sensitive port {log.dst_port} ({service_desc}) from source {log.src_ip}."
        })

    # Rule 4: Rapid Port Sweep Scan
    if log.packet_count > 100 and log.bytes_sent < 2000:
        triggered_rules.append({
            "alert_type": "Reconnaissance / Port Scan",
            "severity": AlertSeverity.MEDIUM,
            "confidence_score": 0.78,
            "summary": f"High packet count ({log.packet_count}) with low payload indicates horizontal port scan from {log.src_ip}."
        })

    return triggered_rules
