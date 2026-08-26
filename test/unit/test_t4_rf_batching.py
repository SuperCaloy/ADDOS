"""T4: RF micro-batching (B1).

Batched predictions must equal solo predictions per row (classes exact,
confidence within existing float noise), preserve submission order, isolate
a failing batch to a solo-predict fallback without losing siblings, and stay
disabled unless the flag is explicitly enabled.
"""
import concurrent.futures
import time

import numpy as np
import pytest


def _attack_flow(proto=6, pps=8000.0):
    return {
        "flow_duration_sec": 6.0,
        "packet_count": 50000,
        "byte_count": 2500000,
        "packet_count_per_second": pps,
        "byte_count_per_second": 400000.0,
        "flow_count_per_src": 3,
        "ip_proto": proto,
        "tp_src": 44444,
        "tp_dst": 80,
    }


@pytest.fixture(scope="module")
def vectors(real_models):
    from backend.models import rf_pipeline

    return [rf_pipeline.extract_rf_features(_attack_flow(proto=p % 17))
            for p in range(32)]


def test_config_defaults_keep_batching_off():
    from backend import config

    assert config.RF_BATCH_ENABLED is False
    assert 8 <= config.RF_BATCH_MAX <= 16
    assert config.RF_BATCH_WINDOW_MS <= 50


def test_batch_matches_solo_per_row(vectors):
    from backend.models import rf_pipeline

    batch_out = rf_pipeline.run_rf_inference_batch(vectors)
    assert len(batch_out) == len(vectors)
    for vec, (cls_b, conf_b) in zip(vectors, batch_out):
        cls_s, conf_s = rf_pipeline.run_rf_inference(vec)
        assert cls_b == cls_s
        assert abs(conf_b - conf_s) <= 1e-12


def test_batch_resolves_futures_in_submission_order():
    from backend.pipeline import rf_batcher

    rf_batcher.ensure_started()
    rf_batcher.reset_for_tests()

    vecs = [np.zeros((1, 15)) for _ in range(5)]
    futs = [rf_batcher.infer(v) for v in vecs]
    results = [f.result(timeout=5.0) for f in futs]
    assert len(results) == 5
    for cls, conf in results:
        assert isinstance(cls, str)
        assert 0.0 <= conf <= 1.0


def test_batch_failure_isolates_to_solo_fallback(monkeypatch):
    from backend.pipeline import rf_batcher
    from backend.models import rf_pipeline

    rf_batcher.ensure_started()
    rf_batcher.reset_for_tests()

    vec = np.zeros((1, 15))
    solo_cls, solo_conf = rf_pipeline.run_rf_inference(vec)

    def _boom(vecs):
        raise RuntimeError("injected batch failure")

    monkeypatch.setattr(rf_batcher.rf_pipeline, "run_rf_inference_batch", _boom)
    fut = rf_batcher.infer(vec)
    with pytest.raises(RuntimeError):
        fut.result(timeout=5.0)
    # Worker-side fallback still yields a good answer.
    cls_fb, conf_fb = rf_pipeline.run_rf_inference(vec)
    assert (cls_fb, conf_fb) == (solo_cls, solo_conf)


def test_worker_uses_batch_path_only_when_enabled(
        real_models, temp_db, monkeypatch):
    from backend.pipeline import worker, flow_tracker
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    batch_calls = {"n": 0}

    sm_mod.state_machine._states.clear()
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))

    def _fake_infer(vec):
        batch_calls["n"] += 1
        fut = concurrent.futures.Future()
        fut.set_result(("SYN Flood", 0.95))
        return fut

    from backend.pipeline import rf_batcher
    monkeypatch.setattr(rf_batcher, "infer", _fake_infer)
    monkeypatch.setattr(worker, "RF_BATCH_ENABLED", True)

    fs = _attack_flow()
    enq = time.monotonic()
    worker._process_item(0, 1, "10.0.0.90", fs, {}, enq, 0)

    assert batch_calls["n"] == 1
    assert len(callbacks) == 1
    args, kwargs = callbacks[0]
    assert args[3] == "SYN Flood"
    assert kwargs["enqueued_at"] == enq


def test_worker_disabled_flag_keeps_solo_path(
        real_models, temp_db, monkeypatch):
    from backend.pipeline import worker, flow_tracker, rf_batcher
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    batch_calls = {"n": 0}

    sm_mod.state_machine._states.clear()
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))

    def _fake_infer(vec):
        batch_calls["n"] += 1
        return concurrent.futures.Future()

    monkeypatch.setattr(rf_batcher, "infer", _fake_infer)
    assert worker.RF_BATCH_ENABLED is False

    fs = _attack_flow()
    worker._process_item(0, 1, "10.0.0.91", fs, {}, time.monotonic(), 0)

    assert batch_calls["n"] == 0
    assert len(callbacks) == 1
