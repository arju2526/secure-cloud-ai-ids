"""Latency / throughput / resource benchmark. Run from backend/ : python3 ../scripts/benchmark_latency.py"""
import os, sys, time, json, statistics, tempfile, platform
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.gettempdir()}/ids_bench.db"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import resource
from types import SimpleNamespace
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine
from app.db.init_db import init_db
from app.services.detection_engine import analyze_log
from app.ml.dataset import generate
Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine); init_db()
recs = generate(500, 125, seed=777)
def pct(v, p): v = sorted(v); return v[min(len(v) - 1, int(len(v) * p / 100))]
lat = []
for r in recs:
    o = SimpleNamespace(**r); t = time.perf_counter(); analyze_log(o); lat.append((time.perf_counter() - t) * 1000)
engine_res = dict(n=len(lat), mean_ms=statistics.mean(lat), p50_ms=pct(lat, 50), p95_ms=pct(lat, 95), p99_ms=pct(lat, 99), max_ms=max(lat))
c = TestClient(app)
tok = c.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
H = {"Authorization": f"Bearer {tok}"}; api = []; errors = 0
t0 = time.perf_counter()
for r in recs[:400]:
    body = {k: r[k] for k in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes_sent", "bytes_received", "packet_count"]}
    t = time.perf_counter(); resp = c.post("/api/v1/detection/analyze", json=body, headers=H); api.append((time.perf_counter() - t) * 1000)
    errors += resp.status_code != 200
total = time.perf_counter() - t0
api_res = dict(n=len(api), mean_ms=statistics.mean(api), p50_ms=pct(api, 50), p95_ms=pct(api, 95), p99_ms=pct(api, 99), throughput_req_per_s=len(api) / total, errors=errors, error_rate=errors / len(api))
res = dict(environment=dict(python=platform.python_version(), platform=platform.platform(), cpus=os.cpu_count(), note="in-process FastAPI TestClient + SQLite, single thread, no network"),
           detection_engine_only=engine_res, api_analyze_endpoint=api_res, peak_rss_MB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
out = os.path.join(os.path.dirname(__file__), "..", "docs", "results"); os.makedirs(out, exist_ok=True)
json.dump(res, open(os.path.join(out, "latency_results.json"), "w"), indent=2); print(json.dumps(res, indent=2))
