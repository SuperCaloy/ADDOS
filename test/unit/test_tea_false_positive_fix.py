"""Tests for TEA Phase 1 false positive fix: std floor + magnitude check.

The bug: when baselines learn from very uniform traffic, variance becomes tiny
(e.g. 1e-6). Even a slight traffic increase produces massive z-scores (1000+),
causing false positive HIGH confidence.
"""
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.config as _cfg
from backend.pipeline.entropy_analyzer import _AdaptiveBaseline


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
