"""T6: observability surface (A4).

Percentile summaries of detection_ms, queue depth gauge, drop counters, and
the honest Detection Time description in the PDF report.
"""
import time

import pytest

from backend.pipeline import worker


@pytest.fixture()
def triage_env(monkeypatch):
    from backend.pipeline import flow_tracker
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))
    monkeypatch.setattr(worker, "_requeue_priority",
                        lambda *a, **kw: None)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    sm_mod.state_machine._states.clear()
    return callbacks


def _flow_stats():
    return {
        "packet_count": 100,
        "packet_count_per_second": 900.0,
        "byte_count": 5000,
        "byte_count_per_second": 45000.0,
        "flow_duration_sec": 2.5,
    }


def test_drop_counter_increments_on_silent_stale_drop(triage_env):
    before = worker.get_drop_counters()["stale_dropped"]
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {},
                         time.monotonic() - 3.5, 0)
    assert worker.get_drop_counters()["stale_dropped"] == before + 1


def test_drop_counter_increments_on_retries_exhausted(triage_env, monkeypatch):
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    before = worker.get_drop_counters()["retries_exhausted"]
    worker._process_item(0, 1, "10.0.0.7", _flow_stats(), {},
                         time.monotonic() - 3.5, 1)
    assert worker.get_drop_counters()["retries_exhausted"] == before + 1


def test_queue_depth_returns_int():
    depth = worker.get_queue_depth()
    assert isinstance(depth, int)
    assert depth >= 0


def test_latency_percentiles_from_recorded_samples():
    from backend.pipeline import decision_engine as de

    de._latency_samples_ms.clear()
    for v in range(1, 101):
        de.record_detection_latency(float(v))
    snap = de.latency_percentiles()
    assert snap["n"] == 100
    assert snap["p50"] == pytest.approx(50.0, abs=1.0)
    assert snap["p95"] >= 94.0
    assert snap["p99"] >= 98.0
    de._latency_samples_ms.clear()


def test_observability_snapshot_shape():
    from backend.pipeline import observability

    snap = observability.build_snapshot()
    # Core keys pinned at A4 time; Task 6 (obs persistence) added the rest.
    assert {"detection_ms", "queue_depth", "drops"} <= set(snap.keys())
    for key in ("submits", "admission", "service", "batch_fallback"):
        assert key in snap
    assert set(snap["detection_ms"].keys()) == {"p50", "p95", "p99", "n"}


def test_report_detection_time_description_is_honest(real_models):
    import inspect
    import backend.api.report as report_mod

    src = inspect.getsource(report_mod)
    assert "attack traffic arrival" not in src
    assert "Average time taken to detect an attack" in src
