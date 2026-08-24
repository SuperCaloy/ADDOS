---
created: 2026-08-19
last-updated: 2026-08-21
status: verified
tags:
  - backend
  - database
---

# Database Layer

**Files:** `backend/database/db.py` (core), `writer.py` (all writes + metric queries), `archiver.py` (rotation).

SQLite at `logs/ddos.db` (gitignored, never committed).

## Core: `database/db.py`

- Single shared connection: `check_same_thread=False`, `journal_mode=WAL`, `synchronous=NORMAL`. Lazy creation + migration via `get_connection()`.
- **Tables:**
  - `mitigation_events` (hot lifecycle ledger; `event_type` = detected | transition | released | manual, nullable `reason`, has `detection_ms`, `mitigation_ms`)
  - `mitigation_events_archive` (rotated copy incl. `event_type`/`reason`; no latency columns)
  - `traffic_summary` (5s-batched counters: total/threats/TN/FP, IF metrics, RF overall + per-class + off-diagonal confusion cells, hold stats)
  - `detection_features` (full per-flow feature snapshot)
  - `quarantine_state` (persisted per-IP state; `block_expires_at` NULL = permanent)
  - `ip_attack_history` (completed attack sessions)
  - `system_metrics` (cpu/mem/pps, controller cpu/mem, `is_attack`, `is_mitigating`)
  - `global_counters` (single-row counters)
- `_migrate()`: idempotent ALTER TABLEs for columns added after initial schema (each in try/except).
- Primitives: `transaction()` context manager (atomic BEGIN/COMMIT/ROLLBACK under a lock; used by archiver), `execute`, `executemany`, `query`.

## Writer: `database/writer.py`

- **Dedup cache** (`_is_duplicate`): 10s TTL keyed `(src_ip, if_score, action_taken, phase)`: phase transitions always log, repeat same-state events don't spam.
- `log_mitigation_event()`, `log_manual_action()` (event_type='manual'), `log_detection_features()`, `save_quarantine_state()`/`delete/load`, `log_traffic_summary()` (buffered, flushed every 5s by `start_flush_thread()`), `log_attack_history()`, `log_system_metrics()`.
- Lifecycle ledger semantics (added 2026-08-21, see [[decisions/mitigation-event-logging-strategy]]): state machine owns transition + released rows (prefilter trip, hold_ip, high-priority ban, escalations, `_clear()` reasons); decision_engine writes one `detected` row per phase entry via `_should_log_detection()` gate keyed on monotonic `phase_entered`; deception emits sinkhole transition + released rows; writer 10s dedup cache kept as safety net.
- **Metric queries:** `get_ml_metrics()` (overall P/R/F1/acc/FPR/FNR/TPR/TNR), `get_if_metrics()`, `get_rf_metrics()` (micro-averaged + per-class + 3x3 confusion matrix), `get_latency_metrics()` (avg detection_ms / mitigation_ms), `get_system_metrics_avg()`, `get_system_metrics_attack_vs_baseline()`.
- Offense history: `get_offense_count()` (decayed), `get_offense_total_count()`, `get_ban_level()`, `get_history_dates()`.

## Archiver: `database/archiver.py`

- Every `ARCHIVE_INTERVAL_S = 3600`s, moves `mitigation_events` rows older than `ARCHIVE_AFTER_HOURS = 24` into `mitigation_events_archive` **atomically** (INSERT then DELETE inside a `transaction()`; rollback on failure).
- `start()` spawns the `db-archiver` daemon thread.

## Related notes

- [[backend/api]]: endpoints that query these tables.
- [[config/config-and-dependencies]]: DB path and tuning constants.