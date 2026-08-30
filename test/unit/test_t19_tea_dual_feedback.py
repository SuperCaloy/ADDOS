"""T19: TEA dual feedback with hysteresis.

Core fix for the stuck-"Attack"-verdict root cause: per-flow IF feedback
must never lock TEA baselines, and only TEA's own verdicts drive a
latched lock/unlock cycle through AND-ed hysteresis (IF streak >= 5 AND
TEA normal streak >= 100 eval intervals, or 30s of attack-free time).
Also covered: per-eval dedup (feedback_tea must count intervals, not
flows), degenerate-interval guard, idle unlock, IP profile TTL, and
locked StateMachine state accessors used by every cross-module reader.
"""
import time
from dataclasses import replace

import pytest

from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer, _IpEntropyProfile


@pytest.fixture()
def ea():
    return EntropyAnalyzer()


def _legit_flow(seed: int) -> dict:
    return {
        "src_ip": f"10.0.0.{(seed % 250) + 1}",
        "packet_count": float(40 + (seed * 7) % 60),
        "byte_count": float(4000 + (seed * 130) % 5000),
        "packet_count_per_second": float(20 + (seed * 3) % 30),
        "byte_count_per_second": float(2000 + (seed * 40) % 3000),
        "ip_proto": 17 if seed % 2 else 6,
    }


def _learn(ea: EntropyAnalyzer, intervals: int = 450) -> None:
    """Push enough legit intervals for all five baselines to learn.

    Need more than TEA_LEARN_INTERVALS (360) because:
    1. is_learned is checked at START of update(), so interval N reflects N-1 state
    2. Learning-phase robust rejection drops outlier samples, so actual
       sample count < interval count. Push 450 to ensure all baselines
       reach 360 accepted samples.
    """
    for i in range(intervals):
        ea._last_eval_time = 0.0
        flows = [_legit_flow(i * 8 + j) for j in range(9)]
        res = ea.update(1, flows)
    assert res["is_learned"] is True


# ── IF feedback: streak-only, never locks ─────────────────────────────────

def test_if_feedback_never_locks_baselines(ea):
    assert ea.is_locked is False
    ea.feedback_if(True)
    ea.feedback_if(True)
    assert ea.is_locked is False


def test_if_feedback_unlock_after_streak(ea):
    # Simulate locked baselines from an earlier latched attack.
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.is_locked is True
    for _ in range(ea_mod.TEA_IF_UNLOCK_STREAK):
        ea.feedback_if(False)
    # IF alone can never satisfy the AND-unlock.
    assert ea.is_locked is True


def test_if_anomaly_decays_instead_of_zeroing(ea):
    for _ in range(4):
        ea.feedback_if(False)
    assert ea.if_normal_streak == 4
    ea.feedback_if(True)
    assert ea.if_normal_streak < 4
    assert ea.if_normal_streak > 0


# ── TEA feedback: latch/unlatch hysteresis ────────────────────────────────

def test_tea_high_confidence_locks_immediately(ea):
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True
    assert ea.is_locked is True


def test_tea_lock_needs_consecutive_attack_intervals(ea):
    ea.feedback_tea(True, "moderate", eval_seq=1)
    assert ea.attack_latched is False
    ea.feedback_tea(True, "moderate", eval_seq=2)
    assert ea.attack_latched is False
    ea.feedback_tea(True, "moderate", eval_seq=3)
    assert ea.attack_latched is True
    assert ea.is_locked is True


def test_and_unlock_requires_both_sides(ea):
    ea.feedback_tea(True, "high", eval_seq=1)
    # Fill both streaks minus one step.
    for seq in range(2, ea_mod.TEA_TEA_UNLOCK_STREAK + 1):
        ea.feedback_tea(False, "low", eval_seq=seq)
    for _ in range(ea_mod.TEA_IF_UNLOCK_STREAK - 1):
        ea.feedback_if(False)
    assert ea.attack_latched is True
    ea.feedback_if(False)
    assert ea.if_normal_streak >= ea_mod.TEA_IF_UNLOCK_STREAK
    ea.feedback_tea(False, "low", eval_seq=ea_mod.TEA_TEA_UNLOCK_STREAK + 1)
    assert ea.attack_latched is False
    assert ea.is_locked is False


def test_attack_interval_resets_tea_streak(ea):
    # While unlatched, an attack interval resets the normal streak.
    ea.feedback_tea(False, "low", eval_seq=1)
    ea.feedback_tea(False, "low", eval_seq=2)
    ea.feedback_tea(True, "moderate", eval_seq=3)
    assert ea.tea_normal_streak == 0
    ea.feedback_tea(True, "moderate", eval_seq=4)
    ea.feedback_tea(True, "moderate", eval_seq=5)
    assert ea.attack_latched is True


# ── Dedup: feedback_tea counts eval intervals, not flows ──────────────────

def test_same_eval_seq_counts_once(ea):
    ea.feedback_tea(True, "high", eval_seq=1)
    for _ in range(200):
        ea.feedback_tea(False, "low", eval_seq=2)  # same cached interval, N flows
    assert ea.tea_normal_streak == 1
    assert ea.attack_latched is True


def test_stale_lower_seq_ignored(ea):
    ea.feedback_tea(False, "low", eval_seq=5)
    assert ea.tea_normal_streak == 1
    ea.feedback_tea(False, "low", eval_seq=3)
    assert ea.tea_normal_streak == 1


def test_none_seq_treated_as_new_event(ea):
    ea.feedback_tea(False, "low")   # legacy callers without seq
    ea.feedback_tea(False, "low")
    assert ea.tea_normal_streak == 2


# ── Idle unlock: zero traffic must still recover ──────────────────────────

def test_idle_unlock_after_quiet_period(ea):
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.is_locked is True
    quiet_now = time.monotonic() + ea_mod.TEA_IDLE_UNLOCK_S + 0.5
    ea.idle_tick(now=quiet_now)
    assert ea.attack_latched is False
    assert ea.is_locked is False


def test_idle_tick_within_window_keeps_latch(ea):
    last = time.monotonic()
    ea.feedback_tea(True, "high", eval_seq=1)
    ea.idle_tick(now=time.monotonic() + 1.0)
    assert ea.attack_latched is True


def test_recent_attack_activity_blocks_idle_unlock(ea):
    late = time.monotonic()
    ea.idle_tick(now=late)
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True


# ── update(): eval_seq stamping, empty-buffer, degenerate guard ───────────

def test_update_stamps_eval_seq(ea):
    res = ea.update(1, [_legit_flow(1)])
    assert res["eval_seq"] == 1
    ea._last_eval_time = 0.0
    res = ea.update(1, [_legit_flow(2)])
    assert res["eval_seq"] == 2


def test_cached_repeat_returns_same_eval_seq(ea):
    ea.update(1, [_legit_flow(1)])
    cached = ea.update(1, [_legit_flow(99)])  # inside 0.5s cache window
    assert cached["eval_seq"] == 1


def test_empty_buffer_preserves_last_result(ea):
    first = ea.update(1, [_legit_flow(1)])
    ea._last_eval_time = 0.0        # force a new eval past the cache window
    res = ea.update(1, [])          # idle gap: update fired with no flows
    assert res["idle"] is True
    assert res["is_learned"] == first["is_learned"]
    # The stored verdict is untouched so gating stays consistent.
    assert ea._global_state.last_result.get("idle") is None


def test_degenerate_interval_suppresses_verdict_and_learning(ea):
    _learn(ea)
    mean_before = ea._global_state.size_base.mean
    ea._last_eval_time = 0.0
    single = dict(_legit_flow(1))
    single["src_ip"] = "10.9.9.9"
    res = ea.update(1, [single])    # 1 flow, far below min-flows guard
    assert res["is_attack_pattern"] is False
    assert res["confidence"] == "low"
    assert res["degenerate_interval"] is True
    assert ea._global_state.size_base.mean == mean_before


# ── Per-IP profile TTL ────────────────────────────────────────────────────

def test_profile_cleanup_removes_only_stale():
    analyzer = EntropyAnalyzer()
    analyzer.update_ip("10.0.0.5", 10.0, 100.0)
    analyzer.update_ip("10.0.0.6", 10.0, 100.0)
    fresh_ts = time.monotonic()
    old_ts = fresh_ts - ea_mod.TEA_IP_PROFILE_TTL_S - 10.0
    analyzer._ip_profiles["10.0.0.6"]._last_update = old_ts
    removed = analyzer.cleanup_stale_profiles()
    assert "10.0.0.6" not in analyzer._ip_profiles
    assert "10.0.0.5" in analyzer._ip_profiles
    assert removed == 1


def test_ip_profile_stamps_last_update(ea):
    ea.update_ip("10.0.0.5", 10.0, 100.0)
    ts = ea._ip_profiles["10.0.0.5"]._last_update
    assert abs(ts - time.monotonic()) < 5.0


# ── StateMachine accessors (Phase A) ──────────────────────────────────────

class TestStateMachineAccessors:
    def _state_machine(self):
        from backend.mitigation.state_machine import StateMachine
        return StateMachine()

    def test_get_state_returns_copy(self):
        sm = self._state_machine()
        from backend.mitigation.state_machine import IpState
        sm._states["10.0.0.7"] = IpState(src_ip="10.0.0.7", phase=2)
        s = sm.get_state("10.0.0.7")
        s.phase = 99
        assert sm._states["10.0.0.7"].phase == 2

    def test_get_state_missing_returns_none(self):
        sm = self._state_machine()
        assert sm.get_state("10.255.255.255") is None

    def test_get_state_fields(self):
        sm = self._state_machine()
        from backend.mitigation.state_machine import IpState
        sm._states["10.0.0.7"] = IpState(src_ip="10.0.0.7", phase=2,
                                         action_taken="Time Ban")
        phase, action = sm.get_state_fields("10.0.0.7", "phase", "action_taken")
        assert phase == 2 and action == "Time Ban"

    def test_get_state_ips(self):
        sm = self._state_machine()
        from backend.mitigation.state_machine import IpState
        sm._states["10.0.0.7"] = IpState(src_ip="10.0.0.7")
        sm._states["10.0.0.8"] = IpState(src_ip="10.0.0.8")
        assert sorted(sm.get_state_ips()) == ["10.0.0.7", "10.0.0.8"]

    def test_get_states_snapshot_is_copy(self):
        sm = self._state_machine()
        from backend.mitigation.state_machine import IpState
        sm._states["10.0.0.7"] = IpState(src_ip="10.0.0.7")
        snap = sm.get_states_snapshot()
        snap["10.0.0.7"].phase = 42
        assert sm._states["10.0.0.7"].phase == 1


# ── ZMQ receiver: attaches eval_seq + per-switch verdicts to flow_stats ───

def test_parse_and_route_attaches_eval_seq(isolated_ea, monkeypatch):
    import json
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
            "packet_count_per_second": 50.0,
            "byte_count": 5000,
            "byte_count_per_second": 5000.0,
            "ip_proto": 6,
        },
        "switch_stats": {},
    }
    zr._parse_and_route(json.dumps(msg).encode())

    assert len(submitted) == 1
    _, fs = submitted[0]
    assert fs["tea_eval_seq"] == isolated_ea._global_state.last_result["eval_seq"]
    assert "tea_attack_pattern" in fs
    assert "tea_confidence" in fs


# ── Worker wiring: feedback emitted on low-rate path (starvation fix) ─────

@pytest.fixture()
def isolated_ea(monkeypatch):
    fresh = EntropyAnalyzer()
    monkeypatch.setattr(ea_mod, "entropy_analyzer", fresh)
    return fresh


def test_low_rate_path_feeds_if_feedback(isolated_ea, monkeypatch):
    from backend.pipeline import worker
    from backend.pipeline import flow_tracker
    from backend.mitigation import state_machine as sm_mod

    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(worker, "_result_callback", lambda *a, **kw: None)
    monkeypatch.setattr(flow_tracker.tracker, "get_cached", lambda ip: None)
    sm_mod.state_machine._states.clear()

    flow = {
        "packet_count": 100,
        "packet_count_per_second": 0.01,
        "byte_count": 5000,
        "byte_count_per_second": 50.0,
        "flow_duration_sec": 2.5,
    }
    worker._process_item(1, 1, "10.0.0.7", flow, {}, time.monotonic(), 0)
    assert isolated_ea.if_normal_streak == 1


def test_full_inference_path_feeds_both_channels(isolated_ea, monkeypatch):
    from backend.pipeline import worker
    from backend.models import if_pipeline
    from backend.models import rf_pipeline
    import numpy as np

    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    monkeypatch.setattr(worker, "_result_callback", lambda *a, **kw: None)
    monkeypatch.setattr(if_pipeline, "extract_if_features",
                        lambda fs: np.zeros(4))
    # IF below threshold (0.1 < 0.99) so the RF stage is never entered.
    monkeypatch.setattr(worker.loader, "if_threshold", 0.99)
    monkeypatch.setattr(worker, "_infer_if", lambda vec: (0.1, False))
    flow = {
        "packet_count": 100,
        "packet_count_per_second": 50.0,
        "byte_count": 5000,
        "byte_count_per_second": 5000.0,
        "flow_duration_sec": 5.0,
        "tea_eval_seq": 7,
        "tea_attack_pattern": True,
        "tea_confidence": "moderate",
    }
    worker._process_item(1, 1, "10.0.0.7", flow, {}, time.monotonic(), 0)
    # IF channel: scored normal → streak up, never locks.
    assert isolated_ea.if_normal_streak == 1
    assert isolated_ea.is_locked is False
    # TEA channel: attached verdict processed once against its own latch.
    assert isolated_ea.tea_normal_streak == 0


# ── Acceptance scenario: attack → stop → verdict must recover ─────────────

class TestAttackStopRecovery:
    """The original bug: TEA verdict stuck on Attack after the attack stops.

    Replicates the full lifecycle with dual feedback + hysteresis:
    lock via sustained attack intervals, stop the attack, let quiet legit
    traffic (with occasional IF false positives) flow, verify recovery.
    """

    def test_latch_releases_after_sustained_quiet_traffic(self):
        ea = EntropyAnalyzer()
        seq = 0

        # Attack running: TEA sees ~4s of attack intervals -> latched.
        for i in range(8):
            seq += 1
            ea.feedback_tea(True, "moderate" if i % 3 else "high", eval_seq=seq)
        assert ea.attack_latched is True

        # Attack stops. Post-attack quiet traffic with IF false positives:
        # decay (not zeroing) keeps the IF side climbing.
        rnd_flows = [("normal", 1), ("normal", 1), ("fp", 2), ("normal", 1)]
        while ea.tea_normal_streak < ea_mod.TEA_TEA_UNLOCK_STREAK:
            seq += 1
            ea.feedback_tea(False, "low", eval_seq=seq)
            # spread IF feedback over intervals like a real quiet network
            if len(rnd_flows) > 0 and (seq % 3 == 0):
                kind, weight = rnd_flows[seq % len(rnd_flows)]
                ea.feedback_if(kind == "fp")
            else:
                ea.feedback_if(False)

        assert ea.attack_latched is False
        assert ea.is_locked is False

    def test_zero_traffic_recovery_via_idle_tick(self):
        ea = EntropyAnalyzer()
        ea.feedback_tea(True, "high", eval_seq=1)
        assert ea.is_locked is True
        # ZMQ receiver calls idle_tick() every second; simulate past the configured idle unlock threshold.
        from backend import config as cfg
        base = time.monotonic()
        for s in range(int(cfg.TEA_IDLE_UNLOCK_S) + 2):
            ea.idle_tick(now=base + float(s))
        assert ea.attack_latched is False
        assert ea.is_locked is False
