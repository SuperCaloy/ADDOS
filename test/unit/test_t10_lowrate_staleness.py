"""T10: low-rate-gate staleness bypass (L0 metric-contamination fix).

The dynamic low-rate gate (worker.py) fires _result_callback with
enqueued_at BEFORE the WORKER_ITEM_TIMEOUT_S staleness gate, so
below-baseline-pps items drained from a backlog record uncapped queue
age as detection_ms with zero inference. Correct behavior: the
staleness gate applies BEFORE the low-rate gate, so stale unflagged
items are dropped exactly like every other stale unflagged item, and
fresh low-rate items keep today's Normal callback.
"""
import time

import pytest

from backend.pipeline import worker


@pytest.fixture()
def low_rate_env(monkeypatch):
    from backend.pipeline import flow_tracker
    from backend.mitigation import state_machine as sm_mod

    callbacks = []
    requeues = []

    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append((a, kw)))
    monkeypatch.setattr(worker, "_requeue_priority",
                        lambda *a, **kw: requeues.append(kw))
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    sm_mod.state_machine._states.clear()
    return {"callbacks": callbacks, "requeues": requeues}


def _low_rate_flow_stats():
    """Mature flow (passes the young-flow gate) with pps below the 0.05 floor."""
    return {
        "packet_count": 100,
        "packet_count_per_second": 0.01,
        "byte_count": 5000,
        "byte_count_per_second": 50.0,
        "flow_duration_sec": 2.5,
    }


def test_stale_low_rate_item_dropped_not_recorded(low_rate_env):
    """A >3.0s-old low-pps unflagged item must NOT reach the callback.

    This is the contamination bug: today it fires the low-rate Normal
    callback with its stale enqueued_at, recording uncapped queue age
    as detection_ms. It must hit the staleness gate first and be
    dropped as stale, exactly like any other stale unflagged item.
    """
    before = worker.get_drop_counters()["stale_dropped"]
    enq = time.monotonic() - 3.1
    worker._process_item(1, 1, "10.0.0.7", _low_rate_flow_stats(), {}, enq, 0)
    assert low_rate_env["callbacks"] == []
    assert worker.get_drop_counters()["stale_dropped"] == before + 1


def test_fresh_low_rate_item_keeps_normal_callback(low_rate_env):
    """Regression guard: fresh low-pps items keep today's behavior."""
    enq = time.monotonic()
    worker._process_item(1, 1, "10.0.0.7", _low_rate_flow_stats(), {}, enq, 0)
    assert len(low_rate_env["callbacks"]) == 1
    args, kwargs = low_rate_env["callbacks"][0]
    assert kwargs.get("enqueued_at") == enq
    assert kwargs["timed_out"] is False
    assert args[1] == 0.0 and args[2] is False  # if_score 0.0, not anomaly


def test_boundary_age_low_rate_item_still_processes(low_rate_env):
    """Age just under the timeout passes the (moved) staleness gate."""
    enq = time.monotonic() - 2.9
    worker._process_item(1, 1, "10.0.0.7", _low_rate_flow_stats(), {}, enq, 0)
    assert len(low_rate_env["callbacks"]) == 1


def test_stale_flagged_item_still_requeues_under_new_gate_order(
        low_rate_env, monkeypatch):
    """Moving the staleness gate must not change the flagged triage path."""
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    before = worker.get_drop_counters()["stale_dropped"]
    enq = time.monotonic() - 3.1
    worker._process_item(0, 1, "10.0.0.7", _low_rate_flow_stats(), {}, enq, 0)
    assert low_rate_env["callbacks"] == []
    assert len(low_rate_env["requeues"]) == 1
    assert worker.get_drop_counters()["stale_dropped"] == before
