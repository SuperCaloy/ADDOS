"""T16: persistence of process CPU and OBS snapshots.

The 2026-08-27 root-cause cycle was blocked three times by the same gap:
only SYSTEM-wide cpu_percent was persisted, so backend starvation could
not be separated from backend inefficiency. This pins the new columns.
"""
import sqlite3

import pytest


def test_system_metrics_has_proc_cpu_column(temp_db):
    conn = sqlite3.connect(temp_db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(system_metrics)")]
    assert "proc_cpu_percent" in cols


def test_log_system_metrics_persists_proc_cpu(temp_db):
    from backend.database import writer

    writer.log_system_metrics(50.0, 100.0, 0.0, is_attack=False,
                              ctrl_cpu=1.0, ctrl_mem=10.0,
                              is_mitigating=False, proc_cpu_percent=37.5)
    conn = sqlite3.connect(temp_db)
    row = conn.execute(
        "SELECT cpu_percent, proc_cpu_percent FROM system_metrics "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert row == (50.0, 37.5)


def test_log_system_metrics_old_signature_still_works(temp_db):
    from backend.database import writer

    writer.log_system_metrics(50.0, 100.0, 0.0, is_attack=False,
                              ctrl_cpu=1.0, ctrl_mem=10.0, is_mitigating=False)
    conn = sqlite3.connect(temp_db)
    row = conn.execute(
        "SELECT proc_cpu_percent FROM system_metrics "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert row == (0.0,)


def test_obs_snapshot_persists(temp_db):
    from backend.database import writer
    from backend.pipeline import decision_engine, worker

    decision_engine._latency_samples_ms.clear()
    decision_engine.record_detection_latency(123.4)
    snap = {
        "detection_ms": decision_engine.latency_percentiles(),
        "queue_depth": worker.get_queue_depth(),
        "drops": worker.get_drop_counters(),
        "submits": worker.get_submit_counters(),
        "admission": worker.get_admission_counters(),
        "service": worker.get_stage_timers(),
        "batch_fallback": worker.get_batch_fallback_counters(),
    }
    writer.log_obs_snapshot(snap)
    conn = sqlite3.connect(temp_db)
    row = conn.execute(
        "SELECT p50, p95, n, queue_depth, drops FROM obs_snapshots "
        "ORDER BY id DESC LIMIT 1").fetchone()
    assert row[0] == pytest.approx(123.4)
    assert row[2] == 1
    assert "stale_dropped" in row[4]


def test_build_snapshot_includes_new_counters():
    from backend.pipeline import observability

    snap = observability.build_snapshot()
    for key in ("submits", "admission", "service", "batch_fallback"):
        assert key in snap
