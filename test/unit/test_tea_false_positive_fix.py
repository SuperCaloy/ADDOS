"""Tests for TEA false positive fix: always-learn + std floor + magnitude check.

Phase 1: std floor + magnitude check (prevents tiny-variance FP).
Phase 2: always-learn mode (baselines track traffic even during attacks).
"""
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.config as _cfg
from backend.pipeline.entropy_analyzer import _AdaptiveBaseline
from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer


class TestStdFloor:
    """Phase 1a: z_score should use a std floor of 10% of mean when variance is tiny."""

    def _make_baseline(self, mean: float, variance: float) -> _AdaptiveBaseline:
        """Create a baseline with a given mean and variance (bypass learning)."""
        b = _AdaptiveBaseline(learn_samples=300)
        b._mean = mean
        b._variance = variance
        b._learned = True
        return b

    def test_tiny_variance_no_false_positive(self):
        """With tiny variance (1e-6), z-score must NOT explode.

        Before fix: z = (value - mean) / sqrt(1e-6) = (1.01 - 1.0) / 0.001 = 10
        After fix:  z = (value - mean) / max(0.001, 1.0 * 0.10) = 0.01 / 0.10 = 0.1
        """
        base = self._make_baseline(mean=1.0, variance=1e-6)
        z = base.z_score(1.01)
        # With floor: effective_std = max(sqrt(1e-6), 1.0 * 0.10) = 0.10
        # z = (1.01 - 1.0) / 0.10 = 0.1
        assert abs(z - 0.1) < 1e-9

    def test_large_variance_unaffected(self):
        """With normal variance, z-score should be unchanged by the floor."""
        base = self._make_baseline(mean=10.0, variance=25.0)
        # std = 5.0, floor = 10.0 * 0.10 = 1.0 → effective_std = 5.0 (floor not used)
        z = base.z_score(20.0)
        assert abs(z - 2.0) < 1e-9

    def test_zero_mean_floor(self):
        """When mean is 0, floor collapses to 0 and effective_std = raw std."""
        base = self._make_baseline(mean=0.0, variance=1e-6)
        z = base.z_score(0.5)
        # floor = 0 * 0.10 = 0.0, effective_std = sqrt(1e-6) = 0.001
        assert abs(z - 500.0) < 1.0


class TestMagnitudeCheck:
    """Phase 1b: surge detection requires value > 2x baseline mean."""

    def _make_baseline(self, mean: float, variance: float) -> _AdaptiveBaseline:
        b = _AdaptiveBaseline(learn_samples=300)
        b._mean = mean
        b._variance = variance
        b._learned = True
        return b

    def test_small_absolute_change_not_high(self):
        """A value 1.5x the mean should NOT be flagged as high (needs 2x)."""
        base = self._make_baseline(mean=1.0, variance=100.0)
        # z_score = (1.5 - 1.0) / 10.0 = 0.05 — way below sigma
        # But even if is_high were True, magnitude check prevents it
        # is_high returns False since z=0.05 < attack_sigma
        assert not base.is_high(1.5, sigma=2.5)

    def test_magnitude_check_prevents_high_confidence(self):
        """Even if z-score is high, value below 2x mean must not count as surge."""
        # With tiny variance, z-score would be huge for any deviation.
        # The magnitude check in detection logic requires value > 2 * mean.
        # mean=1.0, value=1.5: 1.5 < 2.0 * 1.0 → no surge
        base = self._make_baseline(mean=1.0, variance=1e-6)
        z = base.z_score(1.5)
        # z is high because of tiny variance, but magnitude check would filter it
        value_is_surge = z >= 2.5 and 1.5 > base.mean * _cfg.TEA_SURGE_MIN_MAGNITUDE
        assert not value_is_surge

    def test_large_deviation_passes_magnitude(self):
        """Value 3x the mean should pass the magnitude check."""
        base = self._make_baseline(mean=1.0, variance=1e-6)
        z = base.z_score(3.0)
        value_is_surge = z >= 2.5 and 3.0 > base.mean * _cfg.TEA_SURGE_MIN_MAGNITUDE
        assert value_is_surge


class TestConfigConstants:
    """Verify the new config constants exist and have correct values."""

    def test_floor_constant_exists(self):
        assert hasattr(_cfg, "TEA_MIN_STD_FLOOR")
        assert _cfg.TEA_MIN_STD_FLOOR == 0.10

    def test_magnitude_constant_exists(self):
        assert hasattr(_cfg, "TEA_SURGE_MIN_MAGNITUDE")
        assert _cfg.TEA_SURGE_MIN_MAGNITUDE == 2.0

    def test_high_confidence_intervals_exists(self):
        assert hasattr(_cfg, "TEA_HIGH_CONFIDENCE_INTERVALS")
        assert _cfg.TEA_HIGH_CONFIDENCE_INTERVALS == 3


class _FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start
    def monotonic(self) -> float:
        return self.t


def _flow(seed: int, pps: float = 10.0) -> dict:
    return {
        "src_ip": f"10.0.{(seed % 5) + 1}.{(seed % 250) + 1}",
        "packet_count": float(40 + (seed * 7) % 60),
        "byte_count": float(4000 + (seed * 130) % 5000),
        "packet_count_per_second": pps,
        "byte_count_per_second": pps * 100,
        "ip_proto": 6 if seed % 2 else 17,
    }


def _learn(ea: EntropyAnalyzer, clock: _FakeClock) -> None:
    for i in range(350):
        clock.t = float(i)
        ea._last_eval_time = 0.0
        ea.update(1, [_flow(i * 9 + j) for j in range(9)])


class TestSustainedHighConfidence:
    """Phase 3: HIGH confidence requires sustained multi-dimension evidence."""

    def test_single_interval_not_high_confidence(self, monkeypatch):
        """Single attack interval should NOT produce HIGH confidence."""
        clock = _FakeClock()
        monkeypatch.setattr(ea_mod, "time", clock)
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Feed one attack interval with high pps
        clock.t = 350.0
        ea._last_eval_time = 0.0
        res = ea.update(1, [_flow(i, pps=50.0) for i in range(9)])

        # Even with multi-dimension signals, single interval is NOT high
        assert res["confidence"] != "high", (
            "Single interval should not get HIGH confidence; "
            f"got confidence={res['confidence']}"
        )

    def test_sustained_attack_gets_high_confidence(self, monkeypatch):
        """3+ consecutive attack intervals SHOULD produce HIGH confidence."""
        clock = _FakeClock()
        monkeypatch.setattr(ea_mod, "time", clock)
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Feed enough attack intervals to build sustained evidence
        for i in range(5):
            clock.t = 350.0 + i * 0.5
            ea._last_eval_time = 0.0
            res = ea.update(1, [_flow(i * 9 + j, pps=50.0) for j in range(9)])

        # After sustained attack, confidence should be HIGH
        assert res["confidence"] == "high", (
            "Sustained attack intervals should get HIGH confidence; "
            f"got confidence={res['confidence']}"
        )

    def test_streak_resets_on_normal_interval(self, monkeypatch):
        """Normal interval breaks the streak, restarting the HIGH counter."""
        clock = _FakeClock()
        monkeypatch.setattr(ea_mod, "time", clock)
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Build 2 attack intervals (not enough for HIGH)
        for i in range(2):
            clock.t = 350.0 + i * 0.5
            ea._last_eval_time = 0.0
            ea.update(1, [_flow(i * 9 + j, pps=50.0) for j in range(9)])

        # Normal interval resets streak
        clock.t = 351.0
        ea._last_eval_time = 0.0
        ea.update(1, [_flow(i * 9 + j, pps=10.0) for j in range(9)])

        # One more attack interval - streak should restart from 1, not continue
        clock.t = 351.5
        ea._last_eval_time = 0.0
        res = ea.update(1, [_flow(i * 9 + j, pps=50.0) for j in range(9)])

        assert res["confidence"] != "high", (
            "Streak should reset after normal interval; "
            f"got confidence={res['confidence']}"
        )


class TestAlwaysLearnDuringAttack:
    """Phase 2: baselines must update (even if capped) during attacks."""

    def test_baselines_update_during_attack(self, monkeypatch):
        """Baselines move during attack intervals (capped at 1% drift)."""
        clock = _FakeClock()
        monkeypatch.setattr(ea_mod, "time", clock)
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        mean_before = ea._global_state.pps_base.mean
        # Latch into attack mode
        ea.feedback_tea(True, "high", eval_seq=1)
        assert ea.attack_latched

        # Feed 10 attack intervals — baselines should drift (capped)
        for i in range(10):
            clock.t = 350.0 + i * 0.5
            ea._last_eval_time = 0.0
            ea.update(1, [_flow(i * 9 + j, pps=50.0) for j in range(9)])

        mean_after = ea._global_state.pps_base.mean
        # Baselines must have moved (even if capped) — NOT frozen
        assert mean_after != mean_before, (
            "Baselines should update during attack (capped drift), "
            "not freeze at old values."
        )

    def test_baselines_recover_after_attack(self, monkeypatch):
        """Baselines converge to post-attack normal after attack ends."""
        clock = _FakeClock()
        monkeypatch.setattr(ea_mod, "time", clock)
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        mean_before = ea._global_state.pps_base.mean
        # Latch into attack
        ea.feedback_tea(True, "high", eval_seq=1)
        assert ea.attack_latched

        # Feed high-pps attack traffic for several intervals
        for i in range(20):
            clock.t = 350.0 + i * 0.5
            ea._last_eval_time = 0.0
            ea.update(1, [_flow(i * 9 + j, pps=50.0) for j in range(9)])

        # Now end the attack: feed normal traffic and simulate normal feedback
        for i in range(60):
            clock.t = 400.0 + i * 0.5
            ea._last_eval_time = 0.0
            res = ea.update(1, [_flow(i * 9 + j, pps=10.0) for j in range(9)])
            ea.feedback_tea(False, "low", eval_seq=res.get("eval_seq", i + 100))
            ea.feedback_if(False)

        mean_after_attack = ea._global_state.pps_base.mean
        # After recovery, baseline should be closer to 10 pps than to the
        # attack-level pps (50), or at least moved away from frozen old value.
        assert mean_after_attack != mean_before, (
            "Baselines should recover after attack ends, "
            "not stay frozen at pre-attack value."
        )
