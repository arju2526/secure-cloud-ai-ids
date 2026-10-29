"""Labelled synthetic flow generator used for training (benign only) and evaluation (benign + attacks).

IMPORTANT: this is *synthetic* data produced by our own generator, not a public benchmark.
Attack classes deliberately include a "stealth" share whose volumes fall BELOW the static rule
thresholds, and benign traffic includes heavy-tailed legitimate flows (backups, large downloads,
internal SSH/MySQL) so that false positives are possible for both rules and ML.
"""
import numpy as np

LABELS = ["benign", "ddos", "port_scan", "exfiltration", "service_probe"]
PROBE_PORTS = [21, 22, 23, 445, 1433, 3306, 3389]


def _ip(rng, prefix):
    return f"{prefix}.{rng.integers(1, 255)}.{rng.integers(1, 255)}"


def _benign(rng):
    r = rng.random()
    if r < 0.45:   port = 443
    elif r < 0.65: port = 80
    elif r < 0.75: port = 53
    elif r < 0.80: port = 8080
    elif r < 0.84: port = 22      # admin SSH (rule 3 will flag -> rule false positive)
    elif r < 0.86: port = 3306    # internal DB (rule 3 will flag -> rule false positive)
    else:          port = int(rng.choice([8443, 5432, 6379, 9200, 25, 587, 993]))
    if port == 53:
        bs = rng.lognormal(4.8, 0.4); br = rng.lognormal(5.6, 0.5); pk = rng.integers(1, 4)
    else:
        bs = rng.lognormal(7.3, 1.0); br = rng.lognormal(8.3, 1.2)
        pk = max(1, int((bs + br) / rng.uniform(500, 1200)))
    kind = rng.random()
    if kind < 0.03:   # large legit download
        br = rng.lognormal(14.5, 0.6); bs = rng.lognormal(8, 0.5); pk = max(1, int((bs + br) / 1300))
    elif kind < 0.045:  # nightly backup upload
        bs = rng.lognormal(14.6, 0.5); br = rng.lognormal(7.5, 0.6); pk = max(1, int((bs + br) / 1300))
    return port, int(bs), int(br), int(pk)


def _ddos(rng):
    stealth = rng.random() < 0.30
    pk = int(rng.integers(250, 900)) if stealth else int(rng.integers(1000, 30000))
    bs = int(pk * rng.uniform(60, 700)); br = int(rng.integers(0, 400))
    return int(rng.choice([80, 443, 53])), bs, br, pk, stealth


def _scan(rng):
    stealth = rng.random() < 0.40
    pk = int(rng.integers(15, 100)) if stealth else int(rng.integers(101, 600))
    bs = int(pk * rng.uniform(40, 60)); br = int(pk * rng.uniform(0, 40))
    return int(rng.integers(1, 65535)), bs, br, pk, stealth


def _exfil(rng):
    stealth = rng.random() < 0.40
    bs = int(rng.uniform(1e6, 4.9e6)) if stealth else int(rng.uniform(5.1e6, 8e7))
    br = int(rng.integers(40, 900)); pk = max(1, int(bs / rng.uniform(900, 1400)))
    return int(rng.choice([443, 443, 80, 21, 53])), bs, br, pk, stealth


def _probe(rng):
    port = int(rng.choice(PROBE_PORTS))
    bs = int(rng.lognormal(6.5, 0.8)); br = int(rng.lognormal(6.0, 0.8)); pk = int(rng.integers(2, 30))
    return port, bs, br, pk, False


def generate(n_benign, n_per_attack, seed, include_attacks=True):
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(n_benign):
        port, bs, br, pk = _benign(rng)
        out.append(dict(label="benign", stealth=False, src_ip=_ip(rng, "192.168"), dst_ip=_ip(rng, "10.0"),
                        src_port=int(rng.integers(1024, 65535)), dst_port=port, protocol="UDP" if port == 53 else "TCP",
                        bytes_sent=bs, bytes_received=br, packet_count=pk))
    if include_attacks:
        for label, fn in [("ddos", _ddos), ("port_scan", _scan), ("exfiltration", _exfil), ("service_probe", _probe)]:
            for _ in range(n_per_attack):
                port, bs, br, pk, st = fn(rng)
                out.append(dict(label=label, stealth=st, src_ip=_ip(rng, "203.0"), dst_ip=_ip(rng, "10.0"),
                                src_port=int(rng.integers(1024, 65535)), dst_port=port, protocol="TCP",
                                bytes_sent=bs, bytes_received=br, packet_count=pk))
    return out
