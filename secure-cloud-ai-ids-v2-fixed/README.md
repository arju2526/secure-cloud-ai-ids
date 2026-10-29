# Secure Cloud AI IDS

A containerized hybrid Intrusion Detection System (IDS) for cloud/network security demonstrations. It combines deterministic security rules with an Isolation Forest anomaly detector and exposes the results through a FastAPI backend and React SOC dashboard.

## Architecture

```text
Synthetic / Network Traffic
        |
        v
     FastAPI
        |
   Network Log DB
        |
   +----+----+
   |         |
 Rules   Isolation Forest
   |         |
   +----+----+
        |
   Security Alerts
        |
   SQLite / API
        |
 React SOC Dashboard
```

## Features

- JWT authentication with ADMIN and ANALYST roles
- Network-log ingestion and persistence
- Rule-based detection for traffic surges, suspicious services, exfiltration patterns, and reconnaissance
- Isolation Forest anomaly detection using scaled traffic features
- Hybrid alert generation and severity/confidence scoring
- React SOC dashboard with live alert polling
- CSV/JSON report export
- Docker Compose deployment
- Synthetic attack simulator for classroom demonstrations

## Default demo accounts

- `admin` / `admin123`
- `analyst` / `analyst123`

Change these credentials and the `SECRET_KEY` before any real deployment.

## Run with Docker

```bash
docker compose up --build
```

Open the dashboard at `http://localhost`.

## Run the attack simulator

Keep Docker Compose running, then from the repository root:

```bash
python3 scripts/attack_simulator.py
```

The simulator authenticates against the API and generates benign traffic, DDoS-like spikes, port-scan traffic, and SMB-targeting traffic.

## API

- `GET /health`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/register`
- `GET /api/v1/auth/me`
- `POST /api/v1/detection/analyze`
- `GET /api/v1/detection/alerts`

## Important scope

(See `docs/PROGRESS_REPORT.md` for measured limitations.)

The current project uses synthetic traffic and an Isolation Forest trained on synthetic baseline traffic. It is a college prototype, not a production IDS or a substitute for network security monitoring infrastructure.

## Evaluation, tests and reports (added)

```bash
cd backend
python3 -m app.ml.train                      # retrain v2 model (writes joblib + model_meta.json)
python3 -m pytest -v                         # 43 tests
python3 ../scripts/evaluate.py               # precision/recall/F1/FPR, 5 seeds -> docs/results/
python3 ../scripts/benchmark_latency.py      # latency / throughput -> docs/results/
```
- Full technical report: `docs/PROGRESS_REPORT.md`; diagrams: `docs/diagrams/`; screenshots: `docs/screenshots/`; raw results: `docs/results/`.
- Copy `.env.example` to `.env` and set `SECRET_KEY` before `docker compose up`.
- Headline (synthetic data, 5 seeds): hybrid F1 0.859 vs rules-only 0.810; stealth-attack recall 0.716 vs 0.356; ML-only FPR 4.3%; ~15 ms detection latency.
