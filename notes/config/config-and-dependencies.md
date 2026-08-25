---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - config
  - dependencies
---

# Config & Dependencies

## Dependency Stack (`requirements.txt`)

32 lines, grouped by role:

| Package | Version | Runtime Role in ADDOS |
|---|---|---|
| `fastapi` | 0.115.6 | Frontend dashboard API (`frontend/app.py`) |
| `uvicorn[standard]` | 0.32.1 | ASGI server for FastAPI (`frontend/main.py`) |
| `flask` | 3.1.0 | Backend REST API (`backend/main.py`) + blueprints |
| `flask-cors` | 5.0.0 | CORS for Flask backend |
| `jinja2` | 3.1.4 | Server-side templates (`frontend/app.py`) |
| `numpy` | 1.26.4 | Array math in ML pipelines (`if_pipeline.py`, `rf_pipeline.py`) |
| `pandas` | 2.2.3 | DataFrame feature construction |
| `scikit-learn` | 1.4.2 | Models themselves (loaded via joblib) |
| `imbalanced-learn` | 0.12.4 | Training-time only (SMOTE): not imported at runtime |
| `scipy` | 1.13.1 | Training-time only: not imported at runtime |
| `joblib` | 1.4.2 | Model persistence (`loader.py`) |
| `matplotlib` / `seaborn` | 3.9.2 / 0.13.2 | Training visualization only: not imported at runtime |
| `reportlab` | 4.2.5 | PDF telemetry report generation (`backend/api/report.py`) |
| `pyzmq` | 26.2.0 | ZeroMQ bus (controller, receiver, commander) |
| `python-iptables` | 1.2.0 | Declared but **not imported in runtime code** |
| `ryu` | 4.34 | SDN controller framework (`controller/ryu_controller.py`) |
| `eventlet` | 0.34.3 | Ryu's async I/O (`eventlet.monkey_patch()`) |

> [!note] Training vs Runtime deps
> `scipy`, `imbalanced-learn`, `matplotlib`, and `seaborn` are pinned for reproducibility of offline training, but no training scripts exist in the repo.

## Model Feature Contracts

### Isolation Forest (`models/isolation_forest/feature_contract.json`)
- **16 features:** `flow_duration_sec`, `packet_count`, `byte_count`, `packet_count_per_second`, `byte_count_per_second`, `flow_count_per_src`, `tp_src`, `tp_dst`, `ip_proto`, `pkt_byte_rate_ratio`, `avg_bytes_per_pkt`, `flow_intensity`, `port_entropy`, `bytes_per_duration`, `pkt_size_uniformity`, `flow_src_intensity`.
- Anomaly threshold = **0.6092241858026261**.

### Random Forest (`models/random_forest/rf_feature_contract.json`)
- **15 features:** IF's 16 minus `tp_src`, `tp_dst`, `port_entropy`, plus `duration_pkt_ratio`, `pkt_rate_per_duration`.
- Classes (3): `ICMP Flood`, `SYN Flood`, `UDP Flood`. Confidence gate = **0.7**.

## Configuration Constants

### Backend Config (`backend/config.py`)
- ZeroMQ: telemetry `tcp://127.0.0.1:5555`, commands `tcp://127.0.0.1:5556`.
- Flask API: `0.0.0.0:5000`.
- Limits: `FLOW_TRACKER_CAP = 500`, `WORKER_QUEUE_MAXSIZE = 1000`, `INFERENCE_CACHE_TTL_S = 1.0`.
- Flood prefilter: SYN `100/1s`, ICMP `50/1s`, UDP `50/1s`.
- Simulation mode: `SIMULATION_MODE = True` (rate limit pps = 1000).

### Frontend Config (`frontend/config.py`)
- Backend API URL: `http://127.0.0.1:5000`.
- Dashboard host/port: `127.0.0.1:8080`.

## Lockfiles

- `package-lock.json`: 88 bytes, vestigial npm stub (no `package.json` exists in repo).
- `skills-lock.json`: 3.1 KB manifest of 12 installed agent skills.

## Related notes

- [[backend/models]]: model artifacts and contracts.
- [[overview/architecture]]: port bindings and data flow.