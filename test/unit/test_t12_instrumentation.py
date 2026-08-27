"""T12: instrumentation surface.

Submit/requeue counters, origin-tagged latency samples (full, low_rate,
cached), batcher stats for RF and IF trays, worker service-time metrics,
and batch-fallback counters. Legacy latency_percentiles() must keep its
exact shape while new per-origin buckets land beside it.
"""
import concurrent.futures
import inspect
import queue
import time

import numpy as np
import pytest

from backend.pipeline import worker


class _FakeCacheEntry:
    def __init__(self):
        self.if_score = 0.9
        self.is_anomaly = True
        self.attack_class = "SYN Flood"
        self.confidence = 0.99


@pytest.fixture()
def worker_env(monkeypatch):
    """Isolate _process_item from real inference and external state."""
    from backend.pipeline import flow_tracker
    from backend.mitigation import state_machine as sm_mod

    callbacks = []

    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))
    monkeypatch.setattr(worker, "_requeue_priority", lambda *a, **kw: None)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    sm_mod.state_machine._states.clear()
    return callbacks


@pytest.fixture()
def latency_env():
    """Empty the rolling detection_ms samples around each latency test."""
    from backend.pipeline import decision_engine as de

    de._latency_samples_ms.clear()
    yield de
    de._latency_samples_ms.clear()


def _flow_stats():
    """Mature high-rate flow that runs the full inference path."""
    return {
        "packet_count": 50000,
        "packet_count_per_second": 900.0,
        "byte_count": 2500000,
        "byte_count_per_second": 450000.0,
        "flow_duration_sec": 6.0,
    }


def _low_rate_flow_stats():
    """Mature flow (passes the young-flow gate) below the 0.05 pps floor."""
    return {
        "packet_count": 100,
        "packet_count_per_second": 0.01,
        "byte_count": 5000,
        "byte_count_per_second": 50.0,
        "flow_duration_sec": 2.5,
    }


def _drain_worker_queue():
    while True:
        try:
            worker._queue.get_nowait()
        except queue.Empty:
            return


# ── 1. Submit-rate counters ──────────────────────────────────────────────

def test_submit_counter_increments_on_submit():
    counters = worker.get_submit_counters()
    assert isinstance(counters, dict)

    before = counters.get("submitted", 0)
    worker.submit("10.0.0.5", _flow_stats(), {})
    after = worker.get_submit_counters()
    assert after["submitted"] == before + 1
    _drain_worker_queue()


def test_submit_counter_requeued_key_increments_on_priority_requeue():
    before = worker.get_submit_counters().get("requeued", 0)
    worker._requeue_priority("10.0.0.5", {}, {}, 1)
    after = worker.get_submit_counters()
    assert after["requeued"] == before + 1
    _drain_worker_queue()


def test_submit_counter_not_incremented_on_queue_full(monkeypatch):
    class _FullQueue:
        def put_nowait(self, item):
            raise queue.Full()

        def qsize(self):
            return 0

    monkeypatch.setattr(worker, "_queue", _FullQueue())
    before = worker.get_submit_counters().get("submitted", 0)
    queue_full_before = worker.get_drop_counters()["queue_full"]

    worker.submit("10.0.0.5", _flow_stats(), {})

    after = worker.get_submit_counters()
    assert after["submitted"] == before
    assert worker.get_drop_counters()["queue_full"] == queue_full_before + 1


# ── 2. Origin-tagged latency samples ─────────────────────────────────────

def test_latency_percentiles_by_origin_buckets(latency_env):
    de = latency_env
    de.record_detection_latency(100.0, origin="full")
    de.record_detection_latency(110.0, origin="full")
    de.record_detection_latency(200.0, origin="low_rate")

    by_origin = de.latency_percentiles_by_origin()
    assert isinstance(by_origin, dict)
    assert set(by_origin["full"].keys()) >= {"p50", "p95", "p99", "n"}
    assert set(by_origin["low_rate"].keys()) >= {"p50", "p95", "p99", "n"}
    assert by_origin["full"]["n"] == 2
    assert by_origin["low_rate"]["n"] == 1
    assert by_origin["full"]["p50"] == pytest.approx(105.0, abs=5.0)


def test_legacy_percentiles_keep_exact_shape_and_count_all_origins(latency_env):
    """Regression guard: no-origin recording stays valid and legacy
    latency_percentiles() keeps its exact t6 shape, counting every sample
    regardless of origin."""
    de = latency_env
    de.record_detection_latency(10.0)
    de.record_detection_latency(20.0, origin="full")
    de.record_detection_latency(30.0, origin="cached")

    snap = de.latency_percentiles()
    assert set(snap.keys()) == {"p50", "p95", "p99", "n"}
    assert snap["n"] == 3


# ── 3. on_result accepts origin kwarg ────────────────────────────────────

def test_on_result_signature_accepts_origin_kwarg():
    from backend.pipeline import decision_engine as de

    params = inspect.signature(de.on_result).parameters
    assert "origin" in params
    assert params["origin"].default is None


# ── 4. Worker passes origin at callback sites ────────────────────────────

def test_low_rate_callback_carries_low_rate_origin(worker_env):
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.7", _low_rate_flow_stats(), {}, enq, 0)
    assert len(worker_env) == 1
    args, kwargs = worker_env[0]
    assert kwargs.get("origin") == "low_rate"


def test_full_inference_callback_carries_full_origin(
        real_models, worker_env):
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert len(worker_env) == 1
    args, kwargs = worker_env[0]
    assert kwargs.get("origin") == "full"


def test_cached_callback_carries_cached_origin(
        real_models, worker_env, monkeypatch):
    from backend.pipeline import flow_tracker

    monkeypatch.setattr(flow_tracker.tracker, "get_cached",
                        lambda ip: _FakeCacheEntry())
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert len(worker_env) == 1
    args, kwargs = worker_env[0]
    assert kwargs.get("origin") == "cached"


# ── 5. RF batcher stats ──────────────────────────────────────────────────

def test_rf_batcher_stats_shape_and_counts_after_infer(real_models):
    from backend.pipeline import rf_batcher

    rf_batcher.ensure_started()
    rf_batcher.reset_for_tests()

    stats = rf_batcher.stats()
    assert isinstance(stats, dict)
    assert set(stats.keys()) >= {"tray_len", "batches", "items"}
    assert isinstance(stats["tray_len"], int)
    assert stats["tray_len"] >= 0

    fut = rf_batcher.infer(np.zeros((1, 15)))
    fut.result(timeout=5.0)

    stats = rf_batcher.stats()
    assert stats["items"] >= 1
    assert stats["batches"] >= 1


# ── 6. IF batcher stats ──────────────────────────────────────────────────

def test_if_batcher_stats_shape_and_counts_after_infer(real_models):
    from backend.pipeline import if_batcher

    if_batcher.ensure_started()
    if_batcher.reset_for_tests()

    stats = if_batcher.stats()
    assert isinstance(stats, dict)
    assert set(stats.keys()) >= {"tray_len", "batches", "items"}
    assert isinstance(stats["tray_len"], int)
    assert stats["tray_len"] >= 0

    fut = if_batcher.infer(np.zeros((1, 16)))
    fut.result(timeout=5.0)

    stats = if_batcher.stats()
    assert stats["items"] >= 1
    assert stats["batches"] >= 1


# ── 7. Worker service-time metric ────────────────────────────────────────

def test_process_item_with_metrics_fires_callback_and_counts_service(
        real_models, worker_env, monkeypatch):
    from backend.pipeline import flow_tracker

    monkeypatch.setattr(flow_tracker.tracker, "get_cached",
                        lambda ip: _FakeCacheEntry())

    t0 = worker.get_stage_timers()
    worker._process_item_with_metrics(1, 1, "10.0.0.7", _flow_stats(), {},
                                      time.monotonic(), 0)
    t1 = worker.get_stage_timers()

    assert len(worker_env) == 1
    assert t1["service_n"] == t0.get("service_n", 0) + 1
    assert isinstance(t1["service_ms_sum"], float)
    assert t1["service_ms_sum"] > t0.get("service_ms_sum", 0.0)


# ── 8. Batch fallback counters ───────────────────────────────────────────

def test_if_batch_failure_falls_back_to_solo_and_bumps_counter(
        real_models, monkeypatch):
    from backend.models import if_pipeline
    from backend.pipeline import if_batcher

    def _never(v):
        fut = concurrent.futures.Future()
        fut.set_exception(RuntimeError("boom"))
        return fut

    monkeypatch.setattr(if_batcher, "infer", _never)
    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", True)

    vec = np.zeros((1, 16))
    before = worker.get_batch_fallback_counters()

    result = worker._infer_if(vec)
    expected = if_pipeline.run_if_inference(vec)

    assert result == expected
    after = worker.get_batch_fallback_counters()
    assert after["if"] == before.get("if", 0) + 1


def test_rf_batch_failure_falls_back_to_solo_and_bumps_counter(
        real_models, monkeypatch):
    from backend.models import rf_pipeline
    from backend.pipeline import rf_batcher

    def _never(v):
        fut = concurrent.futures.Future()
        fut.set_exception(RuntimeError("boom"))
        return fut

    monkeypatch.setattr(rf_batcher, "infer", _never)
    monkeypatch.setattr(worker, "RF_BATCH_ENABLED", True)

    vec = np.zeros((1, 15))
    before = worker.get_batch_fallback_counters()

    result = worker._infer_rf(vec)
    expected = rf_pipeline.run_rf_inference(vec)

    assert result == expected
    after = worker.get_batch_fallback_counters()
    assert after["rf"] == before.get("rf", 0) + 1
