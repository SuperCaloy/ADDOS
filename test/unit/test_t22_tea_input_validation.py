"""T22: telemetry input validation at the trust boundary.

Attacker-influenceable ZMQ telemetry must not poison the pipeline:
numeric flow fields are clamped to [0, FLOW_FIELD_MAX] at the receiver,
and worker-side TEA feedback drops malformed tea_eval_seq values so a
crafted sequence number cannot dedup-out all later eval intervals.
"""
import json

import pytest

import backend.config as cfg
from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer


@pytest.fixture()
def isolated_ea(monkeypatch):
    fresh = EntropyAnalyzer()
    monkeypatch.setattr(ea_mod, "entropy_analyzer", fresh)
    return fresh


# ── Receiver: clamp malformed numeric flow fields ─────────────────────────

def test_receiver_clamps_malformed_flow_fields():
    from backend.transport import zmq_receiver as zr

    raw = {
        "packet_count": -5,
        "packet_count_per_second": -1.5,
        "byte_count": 1e15,
        "byte_count_per_second": "not-a-number",
        "ip_proto": 6,
    }
    out = zr._sanitize_flow_stats(raw)

    assert out["packet_count"] == 0.0
    assert out["packet_count_per_second"] == 0.0
    assert out["byte_count"] == cfg.FLOW_FIELD_MAX
    assert out["byte_count_per_second"] == 0.0
    assert out["ip_proto"] == 6

    # Non-numeric numeric fields become 0.0.
    non_numeric = zr._sanitize_flow_stats({
        "packet_count": None,
        "byte_count": [1],
        "packet_count_per_second": True,
        "switch_delta_pps": "12",
    })
    assert non_numeric["packet_count"] == 0.0
    assert non_numeric["byte_count"] == 0.0
    assert non_numeric["packet_count_per_second"] == 0.0
    assert non_numeric["switch_delta_pps"] == 0.0

    # Negative values clamp to 0.0, values above the ceiling clamp to max.
    clamped = zr._sanitize_flow_stats({
        "switch_delta_pps": -0.001,
        "packet_count_per_second": 5e9,
    })
    assert clamped["switch_delta_pps"] == 0.0
    assert clamped["packet_count_per_second"] == cfg.FLOW_FIELD_MAX

    # A normal telemetry dict round-trips unchanged.
    normal = {
        "packet_count": 100,
        "byte_count": 5000,
        "packet_count_per_second": 50.0,
        "byte_count_per_second": 5000.0,
        "switch_delta_pps": 25,
        "ip_proto": 6,
    }
    assert zr._sanitize_flow_stats(dict(normal)) == normal


def test_receiver_applies_sanitize_in_parse_path(isolated_ea, monkeypatch):
    from backend.transport import zmq_receiver as zr

    monkeypatch.setattr(zr, "entropy_analyzer", isolated_ea)
    monkeypatch.setattr(zr.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(zr.state_machine, "get_state", lambda ip: None)

    submitted = []
    monkeypatch.setattr(zr.worker, "submit",
                        lambda ip, fs, ss: submitted.append((ip, fs)))

    isolated_ea._last_eval_time = 0.0   # force a real TEA eval
    msg = {
        "type": "flow_stats",
        "src_ip": "10.0.0.7",
        "dpid": 1,
        "flow_stats": {
            "packet_count": 100,
            "packet_count_per_second": -50,
            "byte_count": 1e15,
            "byte_count_per_second": 5000.0,
            "ip_proto": 6,
        },
        "switch_stats": {},
    }
    zr._parse_and_route(json.dumps(msg).encode())

    assert len(submitted) == 1
    _, fs = submitted[0]
    assert fs["packet_count_per_second"] == 0.0
    assert fs["byte_count"] == cfg.FLOW_FIELD_MAX


# ── Worker: malformed tea_eval_seq must not reach feedback_tea ────────────

def test_worker_drops_malformed_tea_eval_seq(isolated_ea):
    from backend.pipeline import worker

    # String seq is not an int: TEA channel must stay untouched.
    worker._emit_feedback(True, {
        "tea_eval_seq": "9",
        "tea_attack_pattern": True,
        "tea_confidence": "high",
    })
    assert isolated_ea._last_tea_eval_seq == -1
    assert isolated_ea.tea_normal_streak == 0

    # Bool seq is dropped like any non-int (bool subclasses int).
    worker._emit_feedback(False, {
        "tea_eval_seq": True,
        "tea_attack_pattern": False,
        "tea_confidence": "low",
    })
    assert isolated_ea.tea_normal_streak == 0

    # A valid seq still passes through and counts one normal interval.
    worker._emit_feedback(False, {
        "tea_eval_seq": 1,
        "tea_attack_pattern": False,
        "tea_confidence": "low",
    })
    assert isolated_ea.tea_normal_streak == 1


# ── Receiver: skip-TEA path must not forward attacker tea_eval_seq ────────

def test_skip_tea_path_drops_attacker_eval_seq(isolated_ea, monkeypatch):
    from types import SimpleNamespace
    from backend.transport import zmq_receiver as zr

    monkeypatch.setattr(zr, "entropy_analyzer", isolated_ea)
    monkeypatch.setattr(zr.flood_filter, "is_flagged_any", lambda ip: False)
    # Phase 2 (quarantine) IP: the _skip_tea branch is taken.
    monkeypatch.setattr(zr.state_machine, "get_state",
                        lambda ip: SimpleNamespace(phase=2))

    submitted = []
    monkeypatch.setattr(zr.worker, "submit",
                        lambda ip, fs, ss: submitted.append((ip, fs)))

    msg = {
        "type": "flow_stats",
        "src_ip": "10.0.0.9",
        "dpid": 1,
        "flow_stats": {
            "packet_count": 100,
            "packet_count_per_second": 50.0,
            "byte_count": 5000,
            "byte_count_per_second": 5000.0,
            "ip_proto": 6,
            "tea_eval_seq": 2 ** 40,   # attacker-crafted blackout seq
        },
        "switch_stats": {},
    }
    zr._parse_and_route(json.dumps(msg).encode())

    assert len(submitted) == 1
    _, fs = submitted[0]
    # The attacker-supplied seq must not survive into the worker: the
    # skip path is TEA-silent and must stay dedup-neutral.
    assert "tea_eval_seq" not in fs
    assert isolated_ea._last_tea_eval_seq == -1
