---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - backend
  - api
---

# REST & SSE API

Flask blueprints under `backend/api/`, registered in `backend/main.py`, served on `0.0.0.0:5000` with CORS enabled.

## Stats: `api/stats.py`

- `GET /api/stats`: summary cards + live chart values (`total_packets`, `malicious_dropped`, `normal_packets`, `active_threats`, `avg_latency_ms`, `fp_rate`) from `decision_engine.get_stats()`.
- `GET /api/model_info`: IF/RF accuracy (from traffic_summary ground truth), thresholds, feature lists, RF classes.
- `GET /api/system_metrics`: latest backend + controller CPU/mem.
- `GET /api/debug/flows`: rolling scan log (last 200 IF evaluations).
- **Ground truth endpoints** (used by topology simulation): `POST /api/attack_ground_truth/start|stop`, `GET /api/attack_ground_truth`. Exposes `get_active_attacks()`.

## Events: `api/events.py`

- `GET /api/events`: **SSE stream** (`text/event-stream`) draining `decision_engine.drain_sse_events()` every 0.5s.
- `GET /api/recent_events`: replays recent mitigation events from DB (limit max 500, optional `since`), for page load / SSE reconnect; confidence as percentage.

## Graph: `api/graph.py`

- `GET /api/graph_history?range=1hr|12hr|24hr|session`: aggregates `traffic_summary` into `GRAPH_BUCKET_COUNT = 60` evenly spaced buckets, normalized to pps (`incoming`, `blocked`, `forwarded`).

## IP detail: `api/ip_detail.py`

- `GET /api/ip_detail/<src_ip>/live`: live drawer data for active IPs only (404 if not active).
- `GET /api/ip_detail/<src_ip>`: full detail: live if active, else DB fallback assembling last mitigation event + detection features + attack history + phase timeline. `is_live` flag tells the UI whether to poll.

## Mitigation (quarantine): `api/mitigation.py`

- `GET /api/quarantine_list`: union of state-machine active list + deception sinkhole list.
- `POST /api/quarantine/release`: manual release; calls `record_false_positive()` + queues baseline restore.
- `POST /api/quarantine/block`: permanent manual blackhole via `state_machine.manual_block()`.
- `POST /api/quarantine/clear_all`.
- `GET /api/pending_restores`: drains `decision_engine.drain_pending_restores()`.
- `POST /api/cache/invalidate`.

## Report: `api/report.py` (ReportLab PDF)

- `GET /api/history_dates`: distinct dates with attack history.
- `POST /api/report`: validates `start_date`/`end_date`, unions hot + archive events, `_build_pdf()` produces a styled A4 PDF:
  - **Section 1** Executive Summary (threat counts, vectors, actions, FP rate)
  - **Section 2** Performance Benchmark: 2a IF metrics + 2x2 confusion matrix, 2b RF micro-averaged + 3x3 confusion matrix, 2c response latency, 2d controller resource overhead
  - **Section 3** Offences Summary (by IP)
  - **Section 4** Chronological Mitigation Log
  - **Section 5** IP Attack History
- ML OFF → report with metrics only. Returns PDF as attachment.

## Consumers

- [[frontend/dashboard]]: every endpoint above is consumed by the dashboard JS.
- [[topology/topology-simulation]]: uses ground truth + quarantine/pending_restores endpoints.