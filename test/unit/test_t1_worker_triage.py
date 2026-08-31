"""T1: worker timeout triage matrix.

Ages around WORKER_ITEM_TIMEOUT_S=3.0 crossed with flagged/unflagged and
retry count must produce exactly: normal processing, silent drop, priority
requeue with a fresh stamp, or the timed_out fallback. enqueued_at must
reach on_result bit-identical to what submit() stamped.
"""
import time

import pytest

from backend.pipeline import worker


class _FakeCacheEntry:
    def __init__(self):
        self.if_score = 0.9
        self.is_anomaly = True
        self.attack_class = "SYN Flood"
        self.confidence = 0.9


@pytest.fixture()
def triage_env(monkeypatch):
    """Isolate _process_item from real inference and external state."""
    from backend.pipeline import flow_tracker, flood_prefilter
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    requeues = []

    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)

    def _requeue(src_ip, flow_stats, switch_stats, retry_count):
        requeues.append(
            (src_ip, flow_stats, switch_stats, retry_count, time.monotonic())
        )

    monkeypatch.setattr(worker, "_requeue_priority", _requeue)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))

    # Locked cached path: no inference runs, callback fires with cached values.
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: _FakeCacheEntry())
    called = {"update_flow": 0}
    real_update = flow_tracker.tracker.update_flow

    def _counting_update(ip, fs):
        called["update_flow"] += 1
        return real_update(ip, fs)

    monkeypatch.setattr(flow_tracker.tracker, "update_flow", _counting_update)

    # No tracked IPs -> cached path is 'locked' via high confidence alone.
    sm_mod.state_machine._states.clear()

    return {
        "callbacks": callbacks,
        "requeues": requeues,
        "update_flow_calls": called,
        "states": sm_mod.state_machine._states,
    }


def _flow_stats():
    return {
        "packet_count": 100,
        "packet_count_per_second": 900.0,
        "byte_count": 5000,
        "byte_count_per_second": 45000.0,
        "flow_duration_sec": 2.5,
    }


def test_fresh_item_processes_and_passes_enqueued_at_bit_identical(triage_env):
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert len(triage_env["callbacks"]) == 1
    args, kwargs = triage_env["callbacks"][0]
    assert kwargs.get("enqueued_at") == enq
    assert kwargs["timed_out"] is False


def test_stale_unflagged_item_dropped_silently(triage_env):
    enq = time.monotonic() - 3.1
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert triage_env["callbacks"] == []
    assert triage_env["requeues"] == []


def test_stale_flagged_item_requeued_once_with_retry_count_incremented(triage_env, monkeypatch):
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    enq = time.monotonic() - 3.1
    before = time.monotonic()
    worker._process_item(0, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert triage_env["callbacks"] == []
    assert len(triage_env["requeues"]) == 1
    src_ip, fs, ss, retry_count, fresh_ts = triage_env["requeues"][0]
    assert src_ip == "10.0.0.7"
    assert retry_count == 1
    assert fresh_ts >= before


def test_stale_flagged_item_exhausts_retries_into_timed_out_fallback(triage_env, monkeypatch):
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    enq = time.monotonic() - 3.1
    worker._process_item(0, 2, "10.0.0.7", _flow_stats(), {}, enq, 1)
    assert triage_env["requeues"] == []
    assert len(triage_env["callbacks"]) == 1
    args, kwargs = triage_env["callbacks"][0]
    assert kwargs["timed_out"] is True
    assert all(v is None for v in args[1:5])


def test_boundary_age_just_under_timeout_is_processed(triage_env):
    enq = time.monotonic() - 2.9
    worker._process_item(1, 1, "10.0.0.7", _flow_stats(), {}, enq, 0)
    assert len(triage_env["callbacks"]) == 1


def test_whitelisted_and_invalid_items_never_reach_callback(triage_env):
    for bad_ip in ("", "0.0.0.0", "10.0.0.26"):
        worker._process_item(1, 1, bad_ip, _flow_stats(), {}, time.monotonic(), 0)
    assert triage_env["callbacks"] == []
