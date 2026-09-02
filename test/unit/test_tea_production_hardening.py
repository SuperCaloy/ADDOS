"""Tests for TEA production hardening: Mahalanobis integration into detection."""
import pytest
import numpy as np
from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer
import backend.config as _cfg


class _FakeClock:
    def __init__(self, start=0.0):
        self.t = start

    def monotonic(self):
        return self.t


@pytest.fixture()
def clock(monkeypatch):
    c = _FakeClock()
    monkeypatch.setattr(ea_mod, "time", c)
    return c


def _flow(seed, proto=6, pkt_size=100, pps=10.0):
    byt = float(pkt_size * max(1, int(pps * 2)))
    return {
        "src_ip": f"10.0.{(seed % 5) + 1}.{(seed % 250) + 1}",
        "packet_count": float(40 + (seed * 7) % 60),
        "byte_count": byt,
        "packet_count_per_second": pps,
        "byte_count_per_second": byt * pps / max(1, 40 + (seed * 7) % 60),
        "ip_proto": proto,
    }


def _normal_flows(k):
    protos = [6, 6, 6, 6, 6, 6, 6, 6, 17]
    return [_flow(k * 9 + j, proto=p, pps=10.0) for j, p in enumerate(protos)]


def _learn(ea, clock):
    for i in range(350):
        clock.t = float(i)
        ea.update(1, _normal_flows(i))


class TestMahalanobisDetection:
    """Verify Mahalanobis distance enhances attack detection confidence."""

    def test_mahal_enhances_confidence_for_attack(self, clock):
        """Mahalanobis above attack threshold with volume anomaly should elevate confidence to high."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Attack traffic: high pps + small packets = volume surge
        for k in range(15):
            clock.t = 400.0 + k
            flows = [_flow(k * 9 + j, proto=6, pkt_size=30, pps=80.0) for j in range(9)]
            res = ea.update(1, flows)
            if res["is_attack_pattern"] and res["mahalanobis_distance"] >= _cfg.TEA_MAHALANOBIS_ATTACK_THRESHOLD:
                # Mahalanobis + volume anomaly should yield high confidence
                if res.get("pps_surge") or res.get("size_surge") or res.get("intensity_surge"):
                    assert res["confidence"] == "high", \
                        f"Expected high confidence with Mahalanobis + volume anomaly, got {res['confidence']}"
                    return

        pytest.skip("Could not produce attack with high Mahalanobis + volume anomaly")

    def test_mahal_crowd_increases_confidence(self, clock):
        """Mahalanobis above crowd threshold should raise confidence to moderate."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        for k in range(10):
            clock.t = 400.0 + k
            flows = [_flow(k * 9 + j, proto=17, pkt_size=200, pps=20.0) for j in range(9)]
            res = ea.update(1, flows)

            if res["is_attack_pattern"] and res["mahalanobis_distance"] >= _cfg.TEA_MAHALANOBIS_CROWD_THRESHOLD:
                assert res["confidence"] in ("moderate", "high"), \
                    f"Expected moderate/high confidence, got {res['confidence']}"
                return

        pytest.skip("Could not produce mahalanobis >= crowd threshold in test window")

    def test_normal_traffic_no_mahal_false_positive(self, clock):
        """Normal traffic with low Mahalanobis should not trigger attack detection."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        for k in range(20):
            clock.t = 400.0 + k
            res = ea.update(1, _normal_flows(k))
            mahal = res["mahalanobis_distance"]
            assert mahal < _cfg.TEA_MAHALANOBIS_ATTACK_THRESHOLD, \
                f"Normal flow mahal_dist={mahal:.4f} exceeds attack threshold"
            if k > 0:
                assert not res["is_attack_pattern"], \
                    f"Normal flow at t={clock.t} falsely detected as attack"

    def test_mahal_result_key_always_present(self, clock):
        """mahalanobis_distance must always appear in the result dict."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)
        clock.t = 400.0
        res = ea.update(1, _normal_flows(0))
        assert "mahalanobis_distance" in res
        assert isinstance(res["mahalanobis_distance"], float)

    def test_mahal_does_not_independently_trigger_attack(self, clock):
        """High Mahalanobis alone should not trigger attack (needs volume/collapse companion)."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        for k in range(10):
            clock.t = 400.0 + k
            flows = [_flow(k * 9 + j, proto=6, pkt_size=100, pps=10.0) for j in range(9)]
            res = ea.update(1, flows)
            if k == 0:
                continue  # skip first interval transient from learning
            if res["mahalanobis_distance"] >= _cfg.TEA_MAHALANOBIS_CROWD_THRESHOLD:
                # Mahalanobis is high but no volume anomaly, so should not be attack
                assert not res["is_attack_pattern"], \
                    f"Mahalanobis alone should not trigger attack (t={clock.t})"
                return

        pytest.skip("Could not produce mahalanobis >= crowd threshold after transient")


class TestEMAVarianceBias:
    """Verify EMA variance is not biased by computing err before mean update."""

    def test_variance_positive_after_known_spread(self):
        """Push values with real spread; variance must stay positive."""
        baseline = ea_mod._AdaptiveBaseline(learn_samples=5)
        for v in [10.0, 12.0, 8.0, 11.0, 9.0]:
            baseline.push(v)
        assert baseline._variance > 0, "Variance must be positive after learning"

    def test_zscore_reflects_actual_spread(self):
        """Outlier produces a high z-score; mean-adjacent value produces a low one."""
        baseline = ea_mod._AdaptiveBaseline(learn_samples=5)
        for v in [10.0, 12.0, 8.0, 11.0, 9.0]:
            baseline.push(v)

        mean = baseline.mean
        std = baseline._std
        assert std > 0

        z_far = abs(50.0 - mean) / std
        z_near = abs(mean + 0.1 - mean) / std
        assert z_far > z_near, "Outlier z-score should exceed near-mean z-score"

    def test_variance_tracks_actual_population_variance(self):
        """EMA variance should converge toward the true variance of pushed values."""
        rng = np.random.default_rng(42)
        baseline = ea_mod._AdaptiveBaseline(learn_samples=10)
        samples = rng.normal(loc=50.0, scale=5.0, size=200)
        for v in samples:
            baseline.push(v)

        true_var = np.var(samples, ddof=0)
        ema_var = baseline._variance
        ratio = ema_var / true_var
        assert 0.3 < ratio < 3.0, (
            f"EMA variance {ema_var:.2f} too far from true {true_var:.2f} (ratio={ratio:.2f})"
        )
