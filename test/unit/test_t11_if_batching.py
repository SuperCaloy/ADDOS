"""T11: IF micro-batching (L1).

Batched IF scoring must equal solo scoring per row (scores within float
noise, identical anomaly verdicts), isolate a failing batch to the
worker-side solo fallback, and stay disabled unless the flag is
explicitly enabled (same conservative rollout as RF batching B1).
Extraction (extract_if_features) mutates running-median state and must
stay per-item sequential: only the score_samples call is batched.
"""
import concurrent.futures
import time

import numpy as np
import pytest


def _flow(proto_seed=0, pps=8000.0):
    return {
        "flow_duration_sec": 6.0,
        "packet_count": 50000 + proto_seed,
        "byte_count": 2500000 + proto_seed * 100,
        "packet_count_per_second": pps,
        "byte_count_per_second": 400000.0,
        "flow_count_per_src": 3,
        "ip_proto": 6 + (proto_seed % 3),
        "tp_src": 44444 + proto_seed,
        "tp_dst": 80,
    }


def test_config_if_batching_enabled_after_run5_rollout():
    """IF_BATCH_ENABLED was flipped True deliberately for the Run 5 benchmark
    (2026-08-27), mirroring B1's rollout; runtime solo fallback preserves
    old behavior on any batch failure, verified in the tests below."""
    from backend import config

    assert config.IF_BATCH_ENABLED is True
    assert 8 <= config.IF_BATCH_MAX <= 16
    assert config.IF_BATCH_WINDOW_MS <= 50


def test_if_batch_matches_solo_per_row(real_models):
    from backend.models import if_pipeline

    vecs = [if_pipeline.extract_if_features(_flow(seed)) for seed in range(16)]
    batch_out = if_pipeline.run_if_inference_batch(vecs)
    assert len(batch_out) == len(vecs)
    for vec, (score_b, anomaly_b) in zip(vecs, batch_out):
        score_s, anomaly_s = if_pipeline.run_if_inference(vec)
        assert anomaly_b == anomaly_s
        assert abs(score_b - score_s) <= 1e-9


def test_if_batch_handles_single_vector(real_models):
    from backend.models import if_pipeline

    vec = if_pipeline.extract_if_features(_flow())
    out = if_pipeline.run_if_inference_batch([vec])
    assert len(out) == 1
    score, anomaly = out[0]
    assert isinstance(score, float)
    assert isinstance(anomaly, bool)


def test_if_batch_failure_raises_through_future(monkeypatch):
    from backend.pipeline import if_batcher
    from backend.models import if_pipeline

    if_batcher.ensure_started()
    if_batcher.reset_for_tests()

    def _boom(vecs):
        raise RuntimeError("injected batch failure")

    monkeypatch.setattr(if_batcher.if_pipeline, "run_if_inference_batch", _boom)
    fut = if_batcher.infer(np.zeros((1, 16)))
    with pytest.raises(RuntimeError):
        fut.result(timeout=5.0)


def test_worker_infer_if_batch_happy_path(real_models, monkeypatch):
    """With the flag on, _infer_if resolves via the batcher future."""
    from backend.pipeline import worker, if_batcher

    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", True)
    if_batcher.ensure_started()
    if_batcher.reset_for_tests()

    vec = np.zeros((1, 16))
    fut_holder = {}

    def _fake_infer(v):
        fut = concurrent.futures.Future()
        fut.set_result((0.4242, False))
        fut_holder["called"] = True
        return fut

    monkeypatch.setattr(if_batcher, "infer", _fake_infer)
    score, anomaly = worker._infer_if(vec)
    assert fut_holder.get("called") is True
    assert (score, anomaly) == (0.4242, False)


def test_worker_infer_if_solo_fallback_on_batch_failure(
        real_models, monkeypatch):
    """Batch-level failure or timeout falls back to solo predict."""
    from backend.pipeline import worker, if_batcher
    from backend.models import if_pipeline

    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", True)

    def _never(v):
        fut = concurrent.futures.Future()
        fut.set_exception(RuntimeError("boom"))
        return fut

    monkeypatch.setattr(if_batcher, "infer", _never)
    vec = np.zeros((1, 16))
    score_fb, anomaly_fb = worker._infer_if(vec)
    score_solo, anomaly_solo = if_pipeline.run_if_inference(vec)
    assert (score_fb, anomaly_fb) == (score_solo, anomaly_solo)


def test_worker_infer_if_solo_when_disabled(real_models, monkeypatch):
    """Flag off: the batcher is never touched (today's behavior)."""
    from backend.pipeline import worker, if_batcher
    from backend.models import if_pipeline

    calls = {"n": 0}

    def _spy(v):
        calls["n"] += 1
        return concurrent.futures.Future()

    monkeypatch.setattr(if_batcher, "infer", _spy)
    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", False)
    vec = np.zeros((1, 16))
    expected = if_pipeline.run_if_inference(vec)
    assert worker._infer_if(vec) == expected
    assert calls["n"] == 0


def test_worker_full_inference_uses_if_batch_path(
        real_models, temp_db, monkeypatch):
    """Full _process_item wiring: callback receives the batched IF score."""
    from backend.pipeline import worker, flow_tracker, if_batcher
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    batch_calls = {"n": 0}

    sm_mod.state_machine._states.clear()
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))
    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", True)

    def _fake_infer(v):
        batch_calls["n"] += 1
        fut = concurrent.futures.Future()
        fut.set_result((0.5, False))
        return fut

    monkeypatch.setattr(if_batcher, "infer", _fake_infer)

    fs = _flow(pps=900.0)
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.92", fs, {}, enq, 0)

    assert batch_calls["n"] == 1
    assert len(callbacks) == 1
    args, kwargs = callbacks[0]
    assert args[1] == 0.5          # if_score came from the batched future
    assert args[2] is False
    assert kwargs["enqueued_at"] == enq
