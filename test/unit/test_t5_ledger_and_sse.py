"""T5: detection ledger, SSE dedup/force, and on_result replay cadence.

Pins the one-detected-row-per-phase-entry gate and SSE emission semantics
that the audit log and expert stream depend on.
"""
import time

import pytest

from backend.database import writer
from backend.pipeline import decision_engine
from backend.mitigation.state_machine import IpState


@pytest.fixture()
def clean_engine(temp_db):
    decision_engine._detection_logged.clear()
    with decision_engine._sse_lock:
        decision_engine._sse_buffer.clear()
        decision_engine._sse_dedup.clear()
    yield decision_engine
    decision_engine._detection_logged.clear()
    with decision_engine._sse_lock:
        decision_engine._sse_buffer.clear()
        decision_engine._sse_dedup.clear()


def test_detection_ledger_suppresses_repeats_per_phase_entry(clean_engine):
    de = clean_engine
    ip = "10.0.0.41"
    pe = 1000.0
    assert de._should_log_detection(ip, pe) is True
    assert de._should_log_detection(ip, pe) is False
    assert de._should_log_detection(ip, pe) is False


def test_detection_ledger_allows_new_phase_entry(clean_engine):
    de = clean_engine
    ip = "10.0.0.42"
    assert de._should_log_detection(ip, 2000.0) is True
    assert de._should_log_detection(ip, 2000.0) is False
    assert de._should_log_detection(ip, 2500.0) is True


def test_sse_dedup_drops_within_ttl(clean_engine):
    de = clean_engine
    ev = {"src_ip": "10.0.0.43", "action_taken": "Quarantined"}
    de._push_sse_event(dict(ev))
    de._push_sse_event(dict(ev))
    de._push_sse_event(dict(ev))
    drained = de.drain_sse_events()
    assert len(drained) == 1
    assert drained[0]["src_ip"] == "10.0.0.43"


def test_sse_force_bypasses_dedup_for_upgrades(clean_engine):
    de = clean_engine
    base = {"src_ip": "10.0.0.44", "action_taken": "Quarantined"}
    de._push_sse_event(dict(base))
    upgrade = {"src_ip": "10.0.0.44", "action_taken": "Time Ban"}
    de._push_sse_event(upgrade, force=True)
    drained = de.drain_sse_events()
    assert len(drained) == 2
    assert drained[-1]["action_taken"] == "Time Ban"


def test_on_result_logs_exactly_one_detected_row_per_phase_entry(
        clean_engine, real_models, monkeypatch):
    de = clean_engine
    ip = "10.0.0.45"
    rows = []
    monkeypatch.setattr(writer, "log_mitigation_event",
                        lambda event: rows.append(event))

    fs = {
        "packet_count": 50000,
        "packet_count_per_second": 8000.0,
        "byte_count": 2500000,
        "byte_count_per_second": 400000.0,
        "flow_duration_sec": 6.0,
        "ip_proto": 6,
        "tea_attack_pattern": True,
        "tea_flash_crowd": False,
        "tea_confidence": "high",
        "tea_is_learned": True,
        "tea_size_var": 1.0,
        "tea_intensity_var": 1.0,
    }
    enq = time.monotonic()
    for _ in range(3):
        de.on_result(ip, 0.95, True, "SYN Flood", 0.91,
                     flow_stats=fs, switch_stats={}, timed_out=False,
                     enqueued_at=enq)

    detected = [r for r in rows if r.get("event_type") == "detected"]
    assert len(detected) == 1
    assert detected[0]["src_ip"] == ip
    assert detected[0]["attack_vector"] in ("SYN Flood", "Uncertain")
    assert detected[0]["detection_ms"] >= 0.0
    # A new phase entry (e.g. after release + re-detect) logs again.
    st = de.state_machine._states.get(ip)
    if st is not None:
        st.phase_entered = time.monotonic() + 5.0
        de.on_result(ip, 0.95, True, "SYN Flood", 0.91,
                     flow_stats=fs, switch_stats={}, timed_out=False,
                     enqueued_at=enq)
        assert len([r for r in rows if r.get("event_type") == "detected"]) == 2


def test_normal_result_counts_traffic_without_mitigation_row(
        clean_engine, real_models, monkeypatch):
    de = clean_engine
    ip = "10.0.0.46"
    rows = []
    summaries = []
    monkeypatch.setattr(writer, "log_mitigation_event",
                        lambda event: rows.append(event))
    monkeypatch.setattr(writer, "log_traffic_summary",
                        lambda **kw: summaries.append(kw))

    fs = {
        "packet_count": 12,
        "packet_count_per_second": 4.0,
        "byte_count": 600,
        "byte_count_per_second": 200.0,
        "flow_duration_sec": 3.0,
    }
    de.on_result(ip, 0.10, False, "Normal", 0.0,
                 flow_stats=fs, switch_stats={}, timed_out=False,
                 enqueued_at=time.monotonic())
    assert [r for r in rows if r.get("event_type") == "detected"] == []
    assert len(summaries) == 1
