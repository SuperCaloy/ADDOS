"""T21: TEA false-positive "Attack" on pure normal traffic.

Reproduces and fixes the self-sustaining deadlock where uniform
legitimate traffic self-latches the attack latch (uniformity and
variance-collapse verdicts against a diverse baseline) and both unlock
paths stay blocked because supervised relearn requires the Isolation
Forest to confirm normal, which it never does when IF also mis-scores
uniform traffic.

Fix under test (notes/tasks/tea-normal-fp-fix-plan.md):
- P1: uniformity-only signals (mechanized_cluster, size/intensity/proto
  collapse) require an attack-scale volume companion (size/intensity
  surge or absolute pps above the learned baseline) before they can set
  an attack verdict. Sigma raised to 2.0 with a 0.9 absolute share
  floor. Low-volume uniformity backstop: very high uniformity from many
  sources still flags at moderate (R1).
- P2: supervised relearn engages from a stable TEA-side "new normal"
  signal while latched, with NO IF confirmation required; it halts the
  instant any attack verdict is seen, and the force path carries a
  per-interval drift cap (REG-1).
- P3: bounded latch max-hold valve requiring sustained TEA silence
  (normal-verdict streak), not merely "no high-conf attack" (REG-2).
- P4: idle unlock IF guard uses a sustained anomaly-rate window, so
  sporadic IF false positives no longer block recovery.
- P5: recovery telemetry export.
- P6: spoofed/malformed tea_eval_seq rejected (analyzer side).
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


# --- fixtures ---------------------------------------------------------------
#
# _mixed_flow builds genuinely diverse legit traffic (two device clusters:
# small-packet clients + large-packet media). The legacy t19/t20 legit
# fixture is itself near-uniform by the uniform_share metric, which masks
# the mechanized_cluster false positive this task fixes.

def _mixed_flow(seed: int) -> dict:
    if seed % 5 < 3:  # small-packet client cluster (~60%)
        pkt = float(10 + (seed * 13) % 20)
        byt = float(500 + (seed * 97) % 400)
        pps = float(5 + (seed * 7) % 10)
        bps = float(400 + (seed * 53) % 300)
    else:             # large-packet media cluster (~40%)
        pkt = float(200 + (seed * 31) % 300)
        byt = float(200000 + (seed * 9973) % 300000)
        pps = float(40 + (seed * 11) % 30)
        bps = float(150000 + (seed * 7919) % 200000)
    return {
        "src_ip": f"10.0.0.{(seed % 200) + 1}",
        "packet_count": pkt,
        "byte_count": byt,
        "packet_count_per_second": pps,
        "byte_count_per_second": bps,
        "ip_proto": 17 if seed % 3 else 6,
    }


def _learn_diverse(ea: EntropyAnalyzer, intervals: int = 16) -> None:
    res = {}
    for i in range(intervals):
        ea._last_eval_time = 0.0
        flows = [_mixed_flow(i * 23 + j) for j in range(20)]
        res = ea.update(1, flows)
    assert res["is_learned"] is True


_UNIFORM_PAYLOAD = {
    "packet_count": 64.0,
    "byte_count": 512.0,
    "ip_proto": 6,
}


def _uniform_flow(i: int, pps: float = 10.0, bps: float = 80.0,
                  ips: int = 250) -> dict:
    f = dict(_UNIFORM_PAYLOAD)
    f["packet_count_per_second"] = pps
    f["byte_count_per_second"] = bps
    f["src_ip"] = f"10.201.{i // ips}.{(i % ips) + 1}"
    return f


# --- P1: uniform legit traffic must not be an attack pattern ----------------

def test_uniform_legit_traffic_not_attack():
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    ea._last_eval_time = 0.0
    res = ea.update(1, [_uniform_flow(j, ips=8) for j in range(9)])
    assert res["is_attack_pattern"] is False
    assert res["confidence"] == "low"
    # Uniformity itself is still detected; it just no longer means attack.
    assert res["mechanized_cluster"] is True


def test_diverse_traffic_remains_normal():
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    ea._last_eval_time = 0.0
    res = ea.update(1, [_mixed_flow(500 + j) for j in range(20)])
    assert res["is_attack_pattern"] is False
    assert res["confidence"] == "low"


def test_uniform_flood_still_latches():
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    latched_at = None
    res = {}
    for i in range(3):
        ea._last_eval_time = 0.0
        res = ea.update(1, [
            _uniform_flow(i * 9 + j, pps=500.0, bps=4000.0, ips=8)
            for j in range(9)
        ])
        ea.feedback_tea(
            bool(res["is_attack_pattern"]),
            str(res.get("confidence", "low")),
            eval_seq=res["eval_seq"],
        )
        if ea.attack_latched:
            latched_at = i + 1
            break
    assert res["is_attack_pattern"] is True
    assert res["confidence"] == "high"      # uniformity + volume companion
    assert latched_at is not None and latched_at <= 3
    assert ea.is_locked is True


def test_low_rate_uniform_flood_still_flagged():
    # R1 backstop: baseline-rate uniform flood from many sources.
    # Per-IP profiles stay "uncertain" at steady low pps, so the global
    # layer must still flag it, at moderate, via the many-source backstop.
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    ea._last_eval_time = 0.0
    res = ea.update(1, [_uniform_flow(200 + j) for j in range(25)])
    assert res["is_attack_pattern"] is True
    assert res["confidence"] == "moderate"


# --- P2: relearn without IF confirmation, with halt + drift cap -------------

def test_relearn_without_if_confirm():
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    for k in range(3):
        ea.feedback_tea(True, "moderate", eval_seq=17 + k)
    assert ea.attack_latched is True
    share_before = ea._global_state.share_base.mean

    if_streak_max = 0
    res = {}
    for i in range(40):
        ea._last_eval_time = 0.0
        res = ea.update(1, [_uniform_flow(i * 9 + j, ips=8) for j in range(9)])
        ea.feedback_tea(
            bool(res["is_attack_pattern"]),
            str(res.get("confidence", "low")),
            eval_seq=res["eval_seq"],
        )
        # Heavy IF mis-scoring of the uniform legit traffic: the IF normal
        # streak must never reach the old relearn gate (5).
        for j in range(9):
            ea.feedback_if(j % 2 == 0)
        if_streak_max = max(if_streak_max, ea.if_normal_streak)

    assert if_streak_max < 5            # old IF-gated relearn could never engage
    share_after = ea._global_state.share_base.mean
    assert share_after > share_before + 0.1   # baselines re-anchored anyway
    assert res["is_attack_pattern"] is False


def test_relearn_halts_on_any_attack_verdict_and_caps_drift():
    # (a) supervised force path carries a per-interval drift cap (REG-1)
    b = _AdaptiveBaseline(ea_mod.TEA_LEARN_INTERVALS)
    b._learned = True
    b._mean = 10.0
    b._variance = 1.0
    b._alpha = 0.02
    b._locked = True
    b.push(1010.0, force=True, max_drift_frac=0.05)
    assert 10.0 < b.mean <= 10.0 * 1.05 + 1e-9

    # (b) P2 stable-moderate trigger: moderates while latched are the
    # frozen-baseline FP signature and BUILD the stability counter.
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    for k in range(3):
        ea.feedback_tea(True, "moderate", eval_seq=17 + k)
    assert ea.attack_latched is True
    share_before = ea._global_state.share_base.mean
    for seq in range(20, 30):
        ea.feedback_tea(True, "moderate", eval_seq=seq)   # inert, stability builds
    assert ea._relearn_stable_streak >= 10

    ea._last_eval_time = 0.0
    res = ea.update(1, [_uniform_flow(j, ips=8) for j in range(9)])
    assert res["is_attack_pattern"] is False
    share_moved = ea._global_state.share_base.mean
    assert share_moved > share_before       # supervised relearn is active

    # High confidence halts relearn instantly (REG-1).
    ea.feedback_tea(True, "high", eval_seq=30)
    assert ea._relearn_stable_streak == 0
    share_frozen = ea._global_state.share_base.mean

    ea._last_eval_time = 0.0
    res2 = ea.update(1, [_uniform_flow(50 + j, ips=8) for j in range(9)])
    ea.feedback_tea(
        bool(res2["is_attack_pattern"]),
        str(res2.get("confidence", "low")),
        eval_seq=31,
    )
    assert ea._global_state.share_base.mean == share_frozen  # no more force-learn

    # A volume-attack snapshot is NEVER force-learned, even with stability
    # fully rebuilt: attack-scale data must not poison the baselines.
    for seq in range(32, 42):
        ea.feedback_tea(True, "moderate", eval_seq=seq)
    assert ea._relearn_stable_streak >= 10
    share_before_flood = ea._global_state.share_base.mean
    ea._last_eval_time = 0.0
    res3 = ea.update(1, [
        _uniform_flow(100 + j, pps=500.0, bps=4000.0, ips=8) for j in range(9)
    ])
    assert res3["is_attack_pattern"] is True
    assert ea._global_state.share_base.mean == share_before_flood


def test_backstop_moderate_latch_recovers_via_relearn(clock):
    # Red-team "stuck-inverse" closure: latched state + legit uniform
    # traffic from MANY sources (backstop moderates, inert while latched)
    # + heavy IF mis-scoring. Inert moderates build the stability counter,
    # backstop-only intervals are relearn-learnable, so the baselines
    # re-anchor, verdicts flip to normal, and the max-hold valve releases
    # the latch. Before the fix this state never recovered.
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    for k in range(3):
        ea.feedback_tea(True, "moderate", eval_seq=17 + k)
    assert ea.attack_latched is True

    unlocked_at = None
    res = {}
    for i in range(400):
        clock.t += 0.5
        ea._last_eval_time = 0.0
        res = ea.update(1, [_uniform_flow(i * 25 + j) for j in range(25)])
        ea.feedback_tea(
            bool(res["is_attack_pattern"]),
            str(res.get("confidence", "low")),
            eval_seq=res["eval_seq"],
        )
        for j in range(25):
            ea.feedback_if(j % 2 == 0)   # IF mis-scores half the flows
        ea.idle_tick(now=clock.t)
        if not ea.attack_latched:
            unlocked_at = i + 1
            break

    assert unlocked_at is not None
    assert res["is_attack_pattern"] is False   # verdict normalized
    assert ea.is_locked is False


# --- P3: bounded latch max-hold safety valve --------------------------------

def test_supervised_relearn_converges_quickly():
    # Post-attack recovery speed: frozen attack-scale baseline (10x the
    # true normal) must re-anchor within ~20 supervised intervals. The
    # drift cap bounds per-interval movement; the relearn alpha must not
    # add a slow EMA tail on top of it.
    from backend import config as cfg

    b = _AdaptiveBaseline(ea_mod.TEA_LEARN_INTERVALS)
    b._learned = True
    b._mean = 100.0    # attack-scale frozen baseline
    b._variance = 400.0
    b._alpha = 0.02
    b._locked = True
    for _ in range(25):
        b.push(10.0, force=True, max_drift_frac=cfg.TEA_RELEARN_MAX_DRIFT_FRAC)
    assert b.mean < 20.0   # 10x shift absorbed to within 2x in ~12.5s


def test_max_hold_unlocks_latched_normal(clock):
    from backend import config as cfg

    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    assert ea.attack_latched is True

    # Uniform legit traffic recovers (TEA normal streak climbs) but IF
    # mis-scores it, blocking both the streak unlock and the idle path.
    for seq in range(2, 122):
        ea.feedback_tea(False, "low", eval_seq=seq)
        ea.feedback_if(seq % 3 == 0)
    assert ea.tea_normal_streak >= ea_mod.TEA_TEA_UNLOCK_STREAK
    assert ea.if_normal_streak < ea_mod.TEA_IF_UNLOCK_STREAK

    clock.t += 60.0
    ea.feedback_if(True)     # keep the IF anomaly rate sustained and fresh
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True    # still inside the max-hold bound

    clock.t += 35.0         # 95s >= TEA_LATCH_MAX_HOLD_S (90)
    ea.feedback_if(True)
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is False
    assert ea.is_locked is False
    assert clock.t - 1000.0 >= cfg.TEA_LATCH_MAX_HOLD_S


def test_max_hold_keeps_real_attack(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    for step in range(1, 26):           # 250s of sustained high-conf attack
        clock.t += 10.0
        ea.feedback_tea(True, "high", eval_seq=step + 1)
        ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True
    assert ea.is_locked is True


def test_max_hold_does_not_unlock_moderate_attack(clock):
    # REG-2: a real attack held at moderate + uniform satisfies any
    # "no high-conf" guard. The valve requires sustained TEA silence
    # (normal-verdict streak), which inert moderates never provide.
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    for step in range(1, 26):           # 250s, well past the 90s hold
        clock.t += 10.0
        ea.feedback_tea(True, "moderate", eval_seq=step + 1)  # inert while latched
        ea.feedback_if(True)            # sustained IF anomalies block idle path
        ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True
    assert ea.is_locked is True


# --- P4: idle unlock tolerates sporadic IF false positives ------------------

def test_idle_unlock_sporadic_if_fp(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    clock.t += 5.0
    for seq in range(2, 42):            # ~10% IF false positives
        ea.feedback_tea(False, "low", eval_seq=seq)
        ea.feedback_if(seq % 10 == 0)
    clock.t += 40.0                     # attack signal quiet for 45s
    ea.feedback_if(True)                # fresh FP timestamp, rate still ~0.14
    ea.idle_tick(now=clock.t)
    # Old code blocked on the fresh IF timestamp alone; the sustained-rate
    # window must let sporadic FPs through.
    assert ea.attack_latched is False
    assert ea.is_locked is False


def test_idle_blocked_sustained_if_anomaly(clock):
    ea = EntropyAnalyzer()
    ea.feedback_tea(True, "high", eval_seq=1)
    clock.t += 5.0
    for seq in range(2, 42):            # ~80% IF anomaly rate
        ea.feedback_tea(False, "low", eval_seq=seq)
        ea.feedback_if(seq % 5 != 0)
    ea.feedback_if(True)                # fresh timestamp, rate ~0.8
    ea.idle_tick(now=clock.t)
    assert ea.attack_latched is True
    assert ea.is_locked is True


# --- P5: recovery telemetry export ------------------------------------------

def test_modest_volume_increase_not_attack():
    # A ~1.5-sigma rise in aggregate pps (legit traffic ramp) must not be
    # an attack pattern. PPS surge sigma is 2.0: real floods are orders of
    # magnitude above baseline, a volume wiggle is not evidence.
    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    ea._last_eval_time = 0.0
    res = ea.update(1, [_uniform_flow(j, pps=28.8, bps=230.0, ips=8) for j in range(9)])
    assert 1.0 < res["pps_zscore"] < 2.0
    assert res["pps_surge"] is False
    assert res["is_attack_pattern"] is False
    assert res["mechanized_cluster"] is True   # uniformity detected, volume-gated


def test_pps_surge_latch_recovers_via_relearn(clock):
    # Live-observed deadlock closure: a sustained step change in legit
    # traffic volume trips pps_surge, latches, and the pps baseline must
    # re-anchor via capped supervised relearn so the latch releases.
    # Before the fix, pps-surge-only intervals were never force-learned
    # (REG-1 over-strict), so the latch cycled forever.
    ea = EntropyAnalyzer()
    _learn_diverse(ea)

    def burst_flows(i):
        # Diverse legit shapes with a 4x pps step: isolates the pps
        # dimension (uniform bursts would add mech/collapse dimensions
        # and legitimately read HIGH, which stays non-relearnable).
        flows = []
        for j in range(20):
            f = _mixed_flow(i * 23 + j)
            f["packet_count_per_second"] = f["packet_count_per_second"] * 4
            flows.append(f)
        return flows

    latched_at = None
    res = {}
    for i in range(400):
        clock.t += 0.5
        ea._last_eval_time = 0.0
        res = ea.update(1, burst_flows(i))
        ea.feedback_tea(
            bool(res["is_attack_pattern"]),
            str(res.get("confidence", "low")),
            eval_seq=res["eval_seq"],
        )
        ea.feedback_if(False)
        if latched_at is None and ea.attack_latched:
            latched_at = i + 1
        if latched_at is not None and not ea.attack_latched:
            break

    assert latched_at is not None          # the surge did latch (volume anomaly)
    assert res["is_attack_pattern"] is False   # baselines re-anchored, verdict normal
    assert ea.attack_latched is False
    assert ea.is_locked is False


def test_telemetry_exports_recovery_metrics(clock):
    ea = EntropyAnalyzer()
    tel = ea.telemetry()
    assert tel["attack_latched"] is False
    assert tel["if_anomaly_rate"] == 0.0

    ea.feedback_tea(True, "high", eval_seq=1)
    ea.feedback_if(True)
    tel = ea.telemetry()
    assert tel["attack_latched"] is True
    assert tel["latch_age_s"] >= 0.0
    assert tel["last_attack_age_s"] >= 0.0
    assert tel["last_if_anomaly_age_s"] >= 0.0
    assert tel["if_anomaly_rate"] > 0.0
    assert "relearn_stable_streak" in tel

    clock.t += 10.0
    tel = ea.telemetry()
    assert tel["latch_age_s"] >= 10.0


def test_expert_exports_tea_telemetry(monkeypatch):
    from backend.api import expert as expert_mod
    from backend.pipeline import entropy_analyzer as ea_mod

    fresh = EntropyAnalyzer()
    monkeypatch.setattr(ea_mod, "entropy_analyzer", fresh)
    monkeypatch.setattr(expert_mod, "entropy_analyzer", fresh)
    tel = expert_mod._tea_telemetry()
    assert "latch_age_s" in tel
    assert "if_anomaly_rate" in tel


def test_expert_exports_learning_interval_denominator():
    # The UI learning progress chip renders "n/<denominator>"; the
    # denominator must come from the live baseline, not a JS constant.
    from flask import Flask
    from backend.api import expert as expert_mod

    ea = EntropyAnalyzer()
    _learn_diverse(ea)
    app = Flask(__name__)
    app.config["TESTING"] = True
    original = expert_mod.entropy_analyzer
    expert_mod.entropy_analyzer = ea
    try:
        with app.app_context():
            data = expert_mod.expert_live().get_json()
    finally:
        expert_mod.entropy_analyzer = original
    tea = data["tea"]["global"]
    assert tea["learned"] is True
    assert tea["learning_intervals"] == ea_mod.TEA_LEARN_INTERVALS
    # PPS observability: the live deadlock diagnosis needed these.
    assert "pps_z" in tea
    assert "pps_baseline" in tea
    assert "pps_surge" in tea
    assert "uniform_backstop" in tea


# --- P6: spoofed eval_seq rejected (analyzer side) ---------------------------

def test_spoofed_eval_seq_rejected():
    ea = EntropyAnalyzer()
    ea.feedback_tea(False, "low", eval_seq=2 ** 40)   # dedup-blackout attempt
    assert ea.tea_normal_streak == 0
    assert ea._last_tea_eval_seq == -1
    ea.feedback_tea(False, "low", eval_seq="7")       # non-int: no crash, no count
    ea.feedback_tea(False, "low", eval_seq=True)      # bool is not a valid seq
    ea.feedback_tea(False, "low", eval_seq=-5)        # negative
    assert ea.tea_normal_streak == 0
    assert ea._last_tea_eval_seq == -1
    ea.feedback_tea(False, "low", eval_seq=1)         # legit traffic still counts
    assert ea.tea_normal_streak == 1
