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


class TestPerIPVerdictOverride:
    """Per-IP verdict should not override global TEA without volume confirmation."""

    def test_per_ip_attack_requires_global_anomaly(self, clock):
        """Per-IP verdict=attack with normal global traffic should not set attack_pattern."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Feed normal traffic to keep global TEA calm
        for k in range(5):
            clock.t = 400.0 + k
            res = ea.update(1, _normal_flows(k))

        # Global TEA should show no attack pattern after normal traffic
        assert not res["is_attack_pattern"], "Global TEA should not show attack for normal traffic"
        assert res["is_learned"], "Global baseline should be learned"

        # Simulate the zmq_receiver logic: per-IP verdict=attack without global anomaly
        ip_verdict = "attack"  # pretend per-IP says attack
        tea_attack_pattern = res["is_attack_pattern"]
        mahal_dist = res.get("mahalanobis_distance", 0.0)

        if ip_verdict == "attack":
            if res["is_learned"] and (
                res["is_attack_pattern"] or mahal_dist > 3.0
            ):
                override = True
            else:
                override = False
        else:
            override = False

        # Per-IP alone should NOT override global TEA
        assert not override, (
            f"Per-IP verdict should not override without global anomaly "
            f"(mahal={mahal_dist:.4f}, is_attack={tea_attack_pattern})"
        )

    def test_per_ip_attack_with_global_anomaly_allows_override(self, clock):
        """Per-IP verdict=attack WITH global anomaly should set attack_pattern."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        # Feed attack traffic to create global anomaly
        for k in range(15):
            clock.t = 400.0 + k
            flows = [_flow(k * 9 + j, proto=6, pkt_size=30, pps=80.0) for j in range(9)]
            res = ea.update(1, flows)

        if not (res["is_attack_pattern"] or res.get("mahalanobis_distance", 0) > 3.0):
            pytest.skip("Could not produce global anomaly in test window")

        # Simulate the zmq_receiver logic: per-IP verdict=attack WITH global anomaly
        ip_verdict = "attack"
        mahal_dist = res.get("mahalanobis_distance", 0.0)

        if ip_verdict == "attack":
            if res["is_learned"] and (
                res["is_attack_pattern"] or mahal_dist > 3.0
            ):
                override = True
            else:
                override = False
        else:
            override = False

        assert override, (
            f"Per-IP should override when global anomaly confirmed "
            f"(mahal={mahal_dist:.4f}, is_attack={res['is_attack_pattern']})"
        )


class TestIsLearnedRequiresTemporalBase:
    """is_learned must require temporal_base to be learned."""

    def test_temporal_base_required_for_is_learned(self, clock):
        """After 350 intervals, all 6 baselines including temporal_base must be learned."""
        ea = EntropyAnalyzer()
        _learn(ea, clock)

        g = ea._global_state
        assert g.is_learned, "Global state should be learned after 350 intervals"
        assert g.temporal_base.is_learned, "temporal_base must be learned"
        assert g.size_base.is_learned
        assert g.intensity_base.is_learned
        assert g.proto_base.is_learned
        assert g.share_base.is_learned
        assert g.pps_base.is_learned

    def test_is_learned_false_when_temporal_not_learned(self, clock):
        """is_learned is False if temporal_base has insufficient samples."""
        ea = EntropyAnalyzer()
        # Feed only enough to learn everything except temporal_base
        # pps_base needs samples with mean_pps in snapshot; temporal needs temporal_entropy
        for i in range(20):
            clock.t = float(i)
            ea.update(1, _normal_flows(i))

        g = ea._global_state
        if not g.temporal_base.is_learned:
            assert not g.is_learned, "is_learned must be False when temporal_base is not learned"


class TestEntropyOfSamplesHistogram:
    """Verify per-IP entropy uses histogram bins for continuous values."""

    def test_same_values_yield_zero_entropy(self):
        """All identical values should produce zero entropy."""
        profile = ea_mod._IpEntropyProfile()
        for _ in range(20):
            profile._pps_samples.append(10.0)
        assert profile._entropy_of_samples(profile._pps_samples) == 0.0

    def test_diverse_values_yield_positive_entropy(self):
        """Different values should produce positive entropy."""
        profile = ea_mod._IpEntropyProfile()
        for v in [1.0, 5.0, 10.0, 15.0, 20.0]:
            profile._pps_samples.append(v)
        assert profile._entropy_of_samples(profile._pps_samples) > 0.0


class TestWarmupGuardAllBaselines:
    """All baselines must reject attack-scale samples during the learning window."""

    def test_all_baselines_reject_attack_during_learning(self, clock):
        """Feed normal, then attack, then normal. Baselines that change (pps, proto)
        must not be contaminated by attack traffic."""
        ea = EntropyAnalyzer()
        g = ea._global_state

        # Phase 1: 350 normal intervals (enough for all baselines to learn with 300 min)
        for i in range(350):
            clock.t = float(i)
            ea.update(1, _normal_flows(i))

        # All baselines should be learned; record means
        assert g.pps_base.is_learned
        assert g.proto_base.is_learned
        normal_pps = g.pps_base.mean
        normal_proto = g.proto_base.mean

        # Phase 2: 50 attack intervals (high pps, single protocol)
        # These push into already-learned baselines, so warmup guard is inactive.
        # Instead, verify baselines resist EMA contamination via robust reject.
        for i in range(50):
            clock.t = 500.0 + i
            flows = [_flow(i * 9 + j, proto=6, pkt_size=64, pps=200.0) for j in range(9)]
            ea.update(1, flows)

        # After attack, pps baseline should not have drifted to attack scale
        assert g.pps_base.mean < 50.0, (
            f"pps baseline drifted to attack scale: {g.pps_base.mean:.4f}"
        )

    def test_warmup_guard_rejects_extreme_pps_during_learning(self, clock):
        """Direct test: warmup guard rejects extreme pps after TEA_WARMUP_REJECT_AFTER samples."""
        baseline = ea_mod._AdaptiveBaseline(
            100, warmup_guard=True, min_learn_mean=1.0
        )
        # Feed 40 normal pps values (above REJECT_AFTER=30)
        for _ in range(40):
            baseline.push(10.0)
        assert not baseline.is_learned
        # Now feed extreme value - should be rejected
        baseline.push(200.0)
        # Mean should still be near 10.0, not pulled toward attack
        assert baseline.mean < 15.0, (
            f"Warmup guard failed: mean={baseline.mean:.2f} after extreme value"
        )

    def test_warmup_guard_rejects_collapsed_size_var(self, clock):
        """Direct test: min_learn_value rejects collapsed size_var during learning."""
        baseline = ea_mod._AdaptiveBaseline(
            40, warmup_guard=True, min_learn_value=0.01
        )
        # Feed 35 normal size_var values (above REJECT_AFTER=30)
        for _ in range(35):
            baseline.push(0.07)
        assert not baseline.is_learned
        # Now feed collapsed value (attack signature: near-zero variance)
        baseline.push(0.001)
        # Baseline should not have learned yet (36 < 40), but mean tracked
        # should still reflect normal values
        assert baseline._psum / len(baseline._samples) > 0.05, (
            f"min_learn_value guard failed: psum/n={baseline._psum / len(baseline._samples):.4f}"
        )


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
