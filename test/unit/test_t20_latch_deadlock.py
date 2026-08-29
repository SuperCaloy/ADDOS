"""T20: latch deadlock fix.

After an attack stops, frozen baselines keep flagging uniform quiet
legit traffic as mechanized_cluster with "moderate" confidence. Under
the old rules every such interval reset _tea_normal_streak and refreshed
_last_attack_event, so both unlock paths (dual streaks and idle timeout)
were blocked for as long as uniform traffic kept flowing. Deadlock.

Fix under test:
- moderate attack verdicts while latched are fully inert (streaks,
  attack streak, attack-event timer untouched) while the eval_seq dedup
  still records the sequence first (RT-1 ordering),
- normal verdicts while latched still climb the dual-streak unlock path,
- high confidence keeps its lock behavior,
- supervised relearning: force push bypasses lock + robust reject at
  min alpha, update() force-learns when IF streak >= 5 while latched,
- idle unlock now also requires IF anomaly silence (RT-C),
- degenerate intervals never learn, supervised or not (RT-5).
"""
import time

import pytest

from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import (
    EntropyAnalyzer,
    _AdaptiveBaseline,
)


class _FakeClock:
    """Deterministic monotonic clock swapped into ea_mod.time."""

    def __init__(self, start: float = 1000.0):
        self.t = start

    def monotonic(self) -> float:
        return self.t


@pytest.fixture()
def clock(monkeypatch):
    c = _FakeClock()
    monkeypatch.setattr(ea_mod, "time", c)
    return c


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


_UNIFORM_PAYLOAD = {
    "packet_count": 64.0,
    "byte_count": 512.0,
    "packet_count_per_second": 10.0,
    "byte_count_per_second": 80.0,
    "ip_proto": 6,
}


def _uniform_flow(i: int) -> dict:
    f = dict(_UNIFORM_PAYLOAD)
    f["src_ip"] = f"10.201.{i // 250}.{(i % 250) + 1}"
    return f


def _learn_legit(ea: EntropyAnalyzer, intervals: int = 65) -> None:
    """Push enough diverse legit intervals through real update() calls."""
    res = {}
    for i in range(intervals):
        ea._last_eval_time = 0.0
        flows = [_legit_flow(i * 8 + j) for j in range(9)]
        res = ea.update(1, flows)
    assert res["is_learned"] is True


def _latch_moderate(ea: EntropyAnalyzer, start_seq: int) -> None:
    for k in range(3):
        ea.feedback_tea(True, "moderate", eval_seq=start_seq + k)
    assert ea.attack_latched is True
    assert ea.is_locked is True


def _prepared_baseline(mean: float = 10.0, variance: float = 1.0) -> _AdaptiveBaseline:
    b = _AdaptiveBaseline(ea_mod.TEA_LEARN_INTERVALS)
    b._learned = True
    b._mean = mean
    b._variance = variance
    b._alpha = 0.05
    b._locked = False
    b._baseline_history = []
    return b


# --- (a) moderate attack verdict while latched must be fully inert ---------

def test_moderate_attack_while_latched_is_inert_but_deduped(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True

    event_ts = ea._last_attack_event
    assert ea.tea_normal_streak == 0
    assert ea._tea_attack_streak == 0

    clock.t += 50.0
    ea.feedback_tea(True, "moderate", eval_seq=2)

    # Streaks and timer untouched by the inert moderate verdict.
    assert ea.tea_normal_streak == 0
    assert ea._last_attack_event == event_ts
    assert ea._tea_attack_streak == 0
    assert ea.attack_latched is True

    # Dedup recorded seq=2 during the early return: replaying seq=2 as a
    # normal verdict must NOT count a second interval.
    ea.feedback_tea(False, "low", eval_seq=2)
    assert ea.tea_normal_streak == 0

    # A fresh sequence counts normally.
    ea.feedback_tea(False, "low", eval_seq=3)
    assert ea.tea_normal_streak == 1


# --- (b) normal verdicts while latched still drive the unlock --------------

def test_normal_verdicts_while_latched_reach_dual_streak_unlock():
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True

    released_at = None
    for seq in range(2, ea_mod.TEA_TEA_UNLOCK_STREAK + 2):
        ea.feedback_tea(False, "low", eval_seq=seq)
        ea.feedback_if(False)
        if not ea.attack_latched:
            released_at = seq
            break

    assert released_at is not None
    assert ea.attack_latched is False
    assert ea.is_locked is False
    assert ea.if_normal_streak >= ea_mod.TEA_IF_UNLOCK_STREAK
    assert ea.tea_normal_streak >= ea_mod.TEA_TEA_UNLOCK_STREAK


# --- (c) high confidence while latched keeps lock behavior -----------------

def test_high_confidence_while_latched_resets_streak_and_refreshes_timer(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True

    event_ts = ea._last_attack_event
    for seq in range(2, 12):
        ea.feedback_tea(False, "low", eval_seq=seq)
    assert ea.tea_normal_streak == 10
    assert ea._last_attack_event == event_ts  # inert lows do not refresh

    clock.t += 200.0
    ea.feedback_tea(True, "high", eval_seq=99)

    assert ea._last_attack_event == clock.t
    assert ea.tea_normal_streak == 0
    assert ea.attack_latched is True


# --- (d) force push bypasses lock and robust reject, pins alpha ------------

def test_force_push_bypasses_lock_and_reject_with_min_alpha():
    b = _prepared_baseline()

    # Unlocked far-value push is robust-rejected.
    far = b.mean + ea_mod.TEA_ROBUST_REJECT_SIGMA * 10.0
    b.push(far)
    assert b.mean == 10.0

    b.lock()
    hist_before = len(b.baseline_history)

    try:
        b.push(far, force=True)
    except TypeError:
        pytest.fail("_AdaptiveBaseline.push does not accept force= (missing behavior)")

    expected_mean = ea_mod.TEA_EMA_ALPHA_MIN * far + (1 - ea_mod.TEA_EMA_ALPHA_MIN) * 10.0
    assert abs(b.mean - expected_mean) < 1e-9
    assert b.alpha == ea_mod.TEA_EMA_ALPHA_MIN
    assert len(b.baseline_history) == hist_before + 1


# --- (e) non-force push on a locked baseline still does nothing ------------

def test_non_force_push_on_locked_baseline_is_noop():
    b = _prepared_baseline()
    b.lock()
    hist_before = len(b.baseline_history)
    var_before = b._variance

    b.push(20.0)

    assert b.mean == 10.0
    assert b.alpha == 0.05
    assert b._variance == var_before
    assert len(b.baseline_history) == hist_before


# --- (f) idle unlock also gated on IF anomaly silence (RT-C) ---------------

def test_idle_unlock_blocked_by_recent_if_anomaly(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True
    assert ea.is_locked is True

    # Attack signal long silent, but an IF anomaly arrives right now.
    clock.t += 100.0
    ea.feedback_if(True)
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True

    # Just inside the IF quiet window: still blocked.
    clock.t = 1000.0 + 100.0 + ea_mod.TEA_IDLE_UNLOCK_S - 1.0
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True

    # Both channels silent past the window: idle release proceeds.
    clock.t += 2.0
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is False
    assert ea.is_locked is False


# --- (g) full deadlock reproduction: latch then uniform quiet traffic ------

class TestLatchDeadlockRecovery:
    def test_uniform_quiet_traffic_releases_latch(self, clock):
        ea = EntropyAnalyzer()

        # Phase 1: learn a diverse baseline through the real update() path.
        _learn_legit(ea)

        share_before = ea._global_state.share_base.mean
        size_before = ea._global_state.size_base.mean

        # Phase 2: latch via sustained moderate attack intervals.
        _latch_moderate(ea, start_seq=ea_mod.TEA_LEARN_INTERVALS + 1)

        # Phase 3: stuck period. Uniform quiet flows keep arriving; TEA
        # verdicts are fed back; IF scores everything normal; the ZMQ
        # receiver's periodic idle tick runs each simulated step.
        gate_hits = 0          # intervals where update()'s own learn moved baselines
        prev_share_mean = ea._global_state.share_base.mean
        released_idx = None

        for i in range(1, 161):
            clock.t += 0.6
            flows = [_uniform_flow(i * 9 + j) for j in range(9)]
            res = ea.update(1, flows)

            if ea.attack_latched:
                cur = ea._global_state.share_base.mean
                if cur != prev_share_mean:
                    gate_hits += 1
                prev_share_mean = cur

            verdict_attack = bool(res["is_attack_pattern"])
            conf = str(res.get("confidence", "low"))
            ea.feedback_tea(verdict_attack, conf, eval_seq=res["eval_seq"])
            for _ in range(9):
                ea.feedback_if(False)

            # Accelerate baseline convergence in-place to simulate many
            # steps of supervised relearning inside one unit-test loop.
            if ea.attack_latched and ea.if_normal_streak >= ea_mod.TEA_IF_UNLOCK_STREAK:
                snap = {
                    "size_var": res["size_var"],
                    "intensity_var": res["intensity_var"],
                    "proto_entropy": res["proto_entropy"],
                    "uniform_share": res["uniform_share"],
                    "unique_ips": res["unique_ips"],
                }
                try:
                    ea._global_state.learn(snap, force=True)
                    ea._global_state.learn(snap, force=True)
                    ea._global_state.learn(snap, force=True)
                except TypeError:
                    pytest.fail("state.learn() does not accept force= (missing behavior)")

            ea.idle_tick(now=clock.t)

            if not ea.attack_latched:
                released_idx = i
                break

        assert released_idx is not None
        assert released_idx <= 120
        # At least one real update() iteration performed its own
        # supervised learn against the live baseline state.
        assert gate_hits >= 1
        # Baselines actually relearned toward the uniform profile.
        share_after = ea._global_state.share_base.mean
        size_after = ea._global_state.size_base.mean
        assert share_after > share_before
        assert size_after < size_before

        # After release the verdict normalizes and the latch stays off.
        normalized_idx = None
        for j in range(40):
            clock.t += 0.6
            flows = [_uniform_flow(10000 + j * 7) for _ in range(9)]
            res2 = ea.update(1, flows)
            ea.feedback_tea(
                bool(res2["is_attack_pattern"]),
                str(res2.get("confidence", "low")),
                eval_seq=res2["eval_seq"],
            )
            for _ in range(9):
                ea.feedback_if(False)
            if not res2["is_attack_pattern"]:
                normalized_idx = j + 1
                break
        assert normalized_idx is not None
        assert ea.attack_latched is False


# --- (h) degenerate intervals never learn, even supervised (RT-5) ----------

def test_degenerate_interval_never_learns_even_supervised():
    ea = EntropyAnalyzer()
    _learn_legit(ea)
    ea.feedback_tea(True, "moderate", eval_seq=17)
    ea.feedback_tea(True, "moderate", eval_seq=18)
    ea.feedback_tea(True, "moderate", eval_seq=19)
    assert ea.attack_latched is True
    for _ in range(6):
        ea.feedback_if(False)   # IF streak >= 5 -> supervised eligible

    means_before = {
        "size": ea._global_state.size_base.mean,
        "intensity": ea._global_state.intensity_base.mean,
        "proto": ea._global_state.proto_base.mean,
        "share": ea._global_state.share_base.mean,
    }

    ea._last_eval_time = 0.0
    res = ea.update(1, [_uniform_flow(1), _uniform_flow(2)])
    assert res["degenerate_interval"] is True

    means_after = {
        "size": ea._global_state.size_base.mean,
        "intensity": ea._global_state.intensity_base.mean,
        "proto": ea._global_state.proto_base.mean,
        "share": ea._global_state.share_base.mean,
    }
    assert means_after == means_before
