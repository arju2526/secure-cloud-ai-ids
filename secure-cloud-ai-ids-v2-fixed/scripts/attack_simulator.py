import json
import random
import sys
import time
import urllib.request

BASE_URL = "http://localhost"
LOGIN_URL = f"{BASE_URL}/api/v1/auth/login"
TARGET_URL = f"{BASE_URL}/api/v1/detection/analyze"


def get_token():
    payload = json.dumps({"username": "admin", "password": "admin123"}).encode()
    request = urllib.request.Request(LOGIN_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())["access_token"]


def generate_packet(traffic_type):
    src_ip = f"192.168.1.{random.randint(10, 250)}"
    dst_ip = "10.0.0.5"
    if traffic_type == "BENIGN":
        return {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(1024, 65535), "dst_port": random.choice([80, 443]), "protocol": "TCP", "bytes_sent": random.randint(200, 5000), "bytes_received": random.randint(500, 15000), "packet_count": random.randint(5, 50)}
    if traffic_type == "DDOS_SPIKE":
        return {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(1024, 65535), "dst_port": 80, "protocol": "UDP", "bytes_sent": random.randint(1_500_000, 5_000_000), "bytes_received": random.randint(100, 500), "packet_count": random.randint(1000, 5000)}
    if traffic_type == "PORT_SCAN":
        return {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(1024, 65535), "dst_port": random.randint(1, 1024), "protocol": "TCP", "bytes_sent": 64, "bytes_received": 0, "packet_count": 600}
    return {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(1024, 65535), "dst_port": 445, "protocol": "TCP", "bytes_sent": 50000, "bytes_received": 120000, "packet_count": 350}


def main():
    print("[IDS Attack Simulator] Authenticating...")
    token = get_token()
    print("[IDS Attack Simulator] Sending synthetic traffic. Press Ctrl+C to stop.\n")
    traffic_types = ["BENIGN", "DDOS_SPIKE", "PORT_SCAN", "EXPLOIT_SMB"]
    weights = [60, 20, 10, 10]
    while True:
        traffic_type = random.choices(traffic_types, weights=weights, k=1)[0]
        payload = generate_packet(traffic_type)
        request = urllib.request.Request(TARGET_URL, data=json.dumps(payload).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                data = json.loads(response.read().decode())
                status = "THREAT" if data.get("threat_detected") else "BENIGN"
                severities = [a["severity"] for a in data.get("triggered_alerts", [])]
                print(f"[{status}] {traffic_type:<12} severity={','.join(severities) or 'LOW'} src={payload['src_ip']}")
        except Exception as exc:
            print(f"[ERROR] {exc}")
        time.sleep(random.uniform(0.5, 1.5))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[IDS Attack Simulator] Stopped.")
        sys.exit(0)
