"""T15: hot-path quiet mode.

HOTPATH_QUIET=True demotes the per-item [SCAN] log.info to log.debug and
skips the per-item expert event push. Both run inside _process_item for
EVERY scored item and burn CPU during waves (verified root cause item 5).
Default False preserves current behavior.
"""
import logging
import time

import pytest

from backend.pipeline import worker


def _flow():
    return {"packet_count": 50000, "packet_count_per_second": 9000.0,
            "byte_count": 2500000, "byte_count_per_second": 400000.0,
            "flow_duration_sec": 6.0, "flow_count_per_src": 3,
            "ip_proto": 6, "tp_src": 44444, "tp_dst": 80}


@pytest.fixture()
def scored_env(monkeypatch, real_models, temp_db):
    from backend.pipeline import flow_tracker
    from backend.mitigation import state_machine as sm_mod

    callbacks, expert = [], []
    sm_mod.state_machine._states.clear()
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    monkeypatch.setattr(worker, "_result_callback",
                        lambda *a, **kw: callbacks.append(kw))
    monkeypatch.setattr(worker, "_push_expert_worker_event",
                        lambda payload: expert.append(payload))
    # Determinism: keep the real rf/if batcher threads out of unit tests.
    monkeypatch.setattr(worker, "RF_BATCH_ENABLED", False)
    monkeypatch.setattr(worker, "IF_BATCH_ENABLED", False)
    # Keep the real tracker singleton untouched across tests.
    monkeypatch.setattr(flow_tracker.tracker, "update_flow", lambda *a, **k: None)
    monkeypatch.setattr(flow_tracker.tracker, "set_cache", lambda *a, **k: None)
    monkeypatch.setattr(flow_tracker.tracker, "invalidate_cache",
                        lambda *a, **k: None)
    return {"callbacks": callbacks, "expert": expert}


def test_default_off_pushes_expert_and_logs_info(scored_env, caplog):
    with caplog.at_level(logging.INFO, logger="backend.pipeline.worker"):
        worker._process_item(1, 1, "10.0.0.9", _flow(), {}, time.monotonic(), 0)
    assert len(scored_env["expert"]) == 1
    assert any("[SCAN]" in r.message for r in caplog.records)


def test_quiet_mode_skips_expert_and_logs_debug_only(scored_env, caplog,
                                                     monkeypatch):
    monkeypatch.setattr(worker, "HOTPATH_QUIET", True)
    with caplog.at_level(logging.INFO, logger="backend.pipeline.worker"):
        worker._process_item(1, 1, "10.0.0.9", _flow(), {}, time.monotonic(), 0)
    assert scored_env["expert"] == []
    assert not any("[SCAN]" in r.message and r.levelno >= logging.INFO
                   for r in caplog.records)
    assert len(scored_env["callbacks"]) == 1  # detection still delivered
