# Secure Cloud AI-IDS — Mid-Term / Phase III Technical Progress Report

All numbers below were produced by scripts in this repository (`scripts/evaluate.py`, `scripts/benchmark_latency.py`, `pytest`) and are stored in `docs/results/`. Data is **synthetic** (own generator); nothing here is a published or expected result.

## 1. System Architecture and Design
Diagrams: `docs/diagrams/architecture.png`, `docs/diagrams/sequence.png`.

| Module | File(s) | Responsibility |
|---|---|---|
| API layer | `app/api/auth.py`, `app/api/detection.py`, `app/api/v1/router.py` | REST endpoints under `/api/v1`; `/health` in `main.py` |
| Security | `app/security/jwt.py` | bcrypt hashing, HS256 JWT (120 min), role guard (`ADMIN`/`ANALYST`) |
| Rule engine | `app/services/rule_engine.py` | 4 deterministic rules (volumetric DDoS, exfiltration, suspicious service port, port scan) |
| ML engine | `app/services/ml_engine.py`, `app/ml/features.py` | Isolation Forest scoring with 7 engineered features, calibrated threshold |
| Hybrid engine | `app/services/detection_engine.py` | Runs both detectors, merges and de-duplicates alerts |
| Persistence | `app/models/entities.py`, `app/db/*` | SQLAlchemy 2 / SQLite: `users`, `network_logs`, `security_alerts` (FK log→alerts) |
| Training | `app/ml/dataset.py`, `app/ml/train.py` | Synthetic flow generator; benign-only fit; threshold calibration |
| Frontend | `frontend/src/App.jsx`, `components/Dashboard.jsx` | Login, 2-second alert polling, CSV/JSON export |
| Tooling | `scripts/attack_simulator.py`, `docker-compose.yml` | Traffic generator; nginx + backend containers |

**Data flow:** client POSTs a flow → JWT validated → `network_logs` row written → rules + ML run → alerts de-duplicated → `security_alerts` rows committed → response returned → dashboard polls `GET /detection/alerts`.
**Design decisions:** hybrid (rules for known signatures, unsupervised ML for statistical outliers, no labelled attack data needed for training); SQLite for a self-contained prototype; shared `features.py` so training and inference cannot drift apart; threshold stored in `model_meta.json` rather than hard-coded.

## 2. Methodology and Implementation
- **Stack:** Python 3.13, FastAPI, SQLAlchemy 2, Pydantic v2, scikit-learn 1.9.1, bcrypt, python-jose; React + Vite + Tailwind; Docker Compose (nginx reverse proxy).
- **Features (v2, `features.py`):** log1p(bytes_sent), log1p(bytes_received), log1p(packets), log1p(bytes/packet), log send/recv ratio, is_web_dns_port, is_privileged_port.
- **Model:** `IsolationForest(n_estimators=200, contamination="auto", random_state=42)` after `StandardScaler`, fitted on 5,000 benign flows (seed 11).
- **Threshold:** 95th percentile of anomaly scores on 2,000 held-out benign validation flows (seed 22) = **0.6265**. The percentile was picked from a sweep (90/95/97/99) on a separate tuning set (seed 33): FPR 8.4 / 3.6 / 1.7 / 0.4 %.
- **Rules:** R1 packets>1000 or bytes_sent>10 MB (CRITICAL); R2 bytes_sent>5 MB and bytes_received<1000 (HIGH); R3 dst_port in {21,22,23,445,1433,3306,3389} (MEDIUM/HIGH); R4 packets>100 and avg bytes/packet<100 (MEDIUM).
- **Integration:** ML severity = score margin over threshold (>0.10 CRITICAL, >0.05 HIGH, else MEDIUM).

## 3. Prototype Development
| Component | Status | Evidence |
|---|---|---|
| Auth (register/login/me/RBAC) | Complete | 6 tests |
| Flow ingestion + persistence | Complete | `test_alert_persisted_and_returned_in_feed` |
| Rule engine (4 rules) | Complete (R4 fixed, see §8) | 15 unit tests |
| ML engine v2 + training pipeline | Complete | `app/ml/`, 11 feature/ML/hybrid tests |
| Dashboard (login, live feed, export) | Complete, manually verified | `docs/screenshots/01–03` |
| Attack simulator | Complete | `docs/results/simulator_run.log` (80 events: 27 THREAT, 53 BENIGN) |
| Evaluation + latency harness | Complete | `scripts/evaluate.py`, `scripts/benchmark_latency.py` |
| Docker Compose deployment | Written, **not executed** (no Docker daemon available in my environment) | `docker-compose.yml` |

Screenshots: `01_login.png`, `02_dashboard.png` (live alerts from the simulator), `03_dashboard_full.png`, `04_api_docs.png` (OpenAPI).

## 4. Dataset and Experimental Setup
- **Source:** own generator `app/ml/dataset.py` (no public dataset used yet).
- **Classes:** benign, ddos, port_scan, exfiltration, service_probe. Attack classes include a **stealth** share (DDoS 30%, scan 40%, exfil 40%) whose volume is *below* the static rule thresholds. Benign traffic includes legitimate heavy-tail flows (3% large downloads, 1.5% nightly backups) and legitimate SSH (4%) / MySQL (2%) so that false positives are possible.
- **Splits (disjoint seeds):** train 11 (5,000 benign), threshold-calibration 22 (2,000 benign), tuning 33, **test 101–105**. Each test seed = 4,000 benign + 4 × 500 attack = 6,000 flows → 30,000 flows total.
- **Environment:** Linux 6.18 x86_64, 2 vCPU, Python 3.13.18, scikit-learn 1.9.1, numpy 2.5.3.
- **Metrics:** accuracy, precision, recall, F1, false-positive rate (FPR), per-class recall, stealth-only recall, ROC-AUC (ML score); mean ± std over 5 seeds.

## 5. Testing and Validation
**43 automated tests, 43 passed** (`docs/results/pytest_output.txt`).
| Group | Tests | What is checked (expected = observed) |
|---|---|---|
| API / auth / validation | 10 | health; 401 without/with bad token; wrong password 401; JWT is real; `/me`; RBAC 403 vs 200 on admin route; register 201 / duplicate 400; payload validation 422; `limit=0` 422 |
| End-to-end detection | 7 | benign (HTTPS) → no threat; SMB, DDoS, port-scan, exfiltration flows → expected alert types/severity; alert persisted and returned with network context |
| Rules | 15 | each rule trigger and non-trigger (e.g. 6 MB upload with large response ≠ exfiltration; bulk transfer ≠ scan); all 7 suspicious ports; severity mapping |
| Features / ML / hybrid | 11 | artifacts + threshold loaded; benign 80/443/53/8080 not flagged (regression); volumetric outlier flagged; score deterministic; benign FP rate < 8% on 1,500 fresh flows; edge case zeros give finite features; hybrid de-duplication |

**Defects found and fixed (all caught by running the code):**
| # | Defect | Evidence | Fix |
|---|---|---|---|
| D1 | Original shipped test `test_benign_traffic_detection` **failed** (1 failed / 6 passed): benign HTTPS flow raised an ML alert | v1 score for port 443 = 0.548 > 0.65-threshold logic, `predict=-1`; cause: raw `dst_port` used as a continuous feature, model trained with port ≈ N(80,20) | v2 feature set (log scale + port-class flags), retrain; regression tests |
| D2 | **Rule 4 could never fire** | 600-packet SYN-scan flow (≥ 40 B headers per packet ⇒ ≥ 24 kB) cannot satisfy `bytes_sent < 2000`; port_scan recall was 0.000 in first evaluation | Changed to avg bytes/packet < 100; port_scan rule recall 0.000 → 0.604 |
| D3 | v1 ML flags almost all realistic benign traffic | FPR 0.933 on test set | retrained v2 FPR 0.043 |
| D4 | Deprecation warning (Pydantic class `Config`) | pytest warning | `ConfigDict` |
| D5 | Hard-coded `SECRET_KEY` in compose; dead shim modules; Dockerfile ran training as a script | code review | `${SECRET_KEY}` + `.env.example`; shims removed; `python -m app.ml.train` |

## 6. Quantitative Results and Performance Analysis
Conditions: 5 test seeds × (4,000 benign + 2,000 attack) synthetic flows; ML v2 threshold 0.6265; mean ± std. (`docs/results/evaluation_results.json`, figures `confusion_matrices.png`, `per_class_recall.png`).

| System | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Rules only | 0.871 ± 0.005 | 0.794 ± 0.012 | 0.828 ± 0.007 | 0.810 ± 0.006 | 0.108 ± 0.009 |
| ML v1 (original) | 0.378 ± 0.003 | 0.349 ± 0.001 | 1.000 ± 0.000 | 0.517 ± 0.001 | 0.933 ± 0.004 |
| ML v2 (retrained) | 0.864 ± 0.003 | 0.887 ± 0.008 | 0.678 ± 0.006 | 0.768 ± 0.005 | 0.043 ± 0.003 |
| Hybrid (Rules + ML v1) | 0.378 ± 0.003 | 0.349 ± 0.001 | 1.000 ± 0.000 | 0.517 ± 0.001 | 0.933 ± 0.004 |
| **Hybrid (Rules + ML v2)** | **0.899 ± 0.006** | 0.803 ± 0.012 | **0.924 ± 0.005** | **0.859 ± 0.007** | 0.114 ± 0.009 |

Per-class detection rate:
| System | ddos | port_scan | exfiltration | service_probe | stealth-only |
|---|---|---|---|---|---|
| Rules only | 0.720 | 0.604 | 0.986 | 1.000 | 0.356 |
| ML v2 | 0.996 | 0.609 | 1.000 | 0.106 | 0.714 |
| Hybrid v2 | 0.998 | 0.698 | 1.000 | 1.000 | 0.716 |

ROC-AUC of the anomaly score: v1 = 0.792 ± 0.006, v2 = 0.963 ± 0.002.
Confusion matrix, Hybrid v2, summed over 5 seeds: TN 17,729 / FP 2,271 / FN 759 / TP 9,241.

**Interpretation.** The hybrid raises F1 from 0.810 (rules) to 0.859 and stealth-attack recall from 0.356 to 0.716, because the ML covers volume-based attacks below rule thresholds while the rules cover service-port probes the ML cannot see (ML-only recall 0.106). The cost: hybrid FPR is 11.4% – dominated by the rules (legitimate SSH/MySQL/backups; Rule 3 alone fires on them), not by the ML (4.3%). ML v1's recall of 1.000 is meaningless since it flags 93% of benign flows. Caveat: v1 was designed for a toy Gaussian distribution; the comparison shows it does not generalize to a realistic traffic mix, not that the idea is flawed.

**Performance** (`docs/results/latency_results.json`; in-process FastAPI TestClient, SQLite, single thread, 2 vCPU):
| Metric | Value |
|---|---|
| Detection engine only (n=1,000) | mean 15.5 ms, p50 15.9, p95 20.4, p99 22.5, max 37.3 ms |
| `POST /analyze` end-to-end (n=400) | mean 27.3 ms, p95 34.5, p99 40.0 ms |
| Throughput | 36.6 requests/s, 0 errors / 400 |
| Peak memory | 206 MB RSS |

## 7. Integration and Verification
- Module chain API → JWT → DB → rules + ML → alerts → DB → feed verified by 7 end-to-end tests.
- Frontend ↔ backend verified manually: Vite dev server proxied `/api` to uvicorn; login via UI, simulator sent 80 flows through the proxy, dashboard displayed 50 recorded alerts (HIGH/CRITICAL/MEDIUM) (`02_dashboard.png`, `simulator_run.log`).
- Interface compatibility: Pydantic schemas validate input (422 on invalid IPs/ports/negative bytes); `AlertResponse` exposes network-log context fields consumed by the dashboard.
- **Not verified:** `docker compose up` (no Docker daemon in the test environment) — to be run on the team machine before submission.

## 8. Technical Challenges and Limitations
1. **Synthetic data only.** Attack labels come from our own generator; results show relative behaviour of the detectors, not real-world accuracy. Rules and generator share thresholds' neighbourhood (partial circularity) – mitigated by stealth variants and a held-out seed set, not eliminated.
2. **Rule false positives (FPR ≈ 10.8%)**: Rules R1/R3 cannot distinguish admin SSH, internal MySQL or backups from attacks. Proposed: per-asset allow-lists, rate-over-time windows.
3. **ML blind spots:** port-scan recall 0.61, service-probe recall 0.11 (ML-only) – these attacks are in-distribution by volume. Flow-level features cannot see "many ports from one source"; needs per-source aggregation windows.
4. **Latency bottleneck:** 15 ms per flow in the detector, dominated by scikit-learn single-sample scoring through 200 trees; throughput 36 req/s. Proposed: batch scoring / smaller forest / ONNX export.
5. **Failed experiments:** first v2 threshold (99th pct) gave F1 0.437 (recall 0.283) and, together with the unsatisfiable R4, hybrid recall 0.673; documented in `docs/results/iteration1_*`; operating point moved to 95th percentile via a tuning-seed sweep.
6. **Security:** demo accounts `admin/admin123` seeded; public `/register` accepts a `role` field (privilege escalation risk) – should be restricted before real use. SQLite, no rate limiting, no HTTPS.
7. Frontend has no automated tests; only live-polling table (no charts yet).

## 9. Milestone Achievement and Future Work
| Status | Item |
|---|---|
| **Completed** | FastAPI backend, JWT + RBAC, DB schema, 4 rules, Isolation Forest v2 + retraining pipeline, hybrid merge, dashboard with export, simulator, 43 tests, evaluation harness, latency benchmark, architecture docs, defect fixes D1–D5 |
| **Partially implemented** | Docker deployment (files written, not executed); security hardening (secret externalised, but open role registration and demo accounts remain); frontend (feed only) |
| **Ongoing** | Validation on a public labelled dataset (CICIDS2017 / UNSW-NB15) with feature mapping from flow records |
| **Planned** | Per-source aggregation features (scan detection); allow-listing to cut rule FPs; batch/ONNX inference; restrict `/register`; dashboard charts and alert status workflow; load test with real HTTP client; CI pipeline |
