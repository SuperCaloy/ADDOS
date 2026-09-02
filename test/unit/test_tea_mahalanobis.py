"""Test Mahalanobis distance for multi-dimensional attack detection."""
import pytest
import numpy as np
from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer


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


def test_mahalanobis_in_result(clock):
    """Result should contain mahalanobis_distance."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)
    clock.t = 400.0
    res = ea.update(1, _normal_flows(0))
    assert "mahalanobis_distance" in res
    assert isinstance(res["mahalanobis_distance"], float)


def test_normal_traffic_low_distance(clock):
    """Normal traffic should have low Mahalanobis distance."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)
    clock.t = 400.0
    res = ea.update(1, _normal_flows(0))
    assert res["mahalanobis_distance"] < 3.0


def test_attack_traffic_high_distance(clock):
    """Attack traffic should have high Mahalanobis distance."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    # Uniform attack traffic
    for k in range(10):
        clock.t = 400.0 + k
        attack_flows = [_flow(k * 9 + j, proto=6, pkt_size=64, pps=50.0) for j in range(9)]
        res = ea.update(1, attack_flows)

    assert res["mahalanobis_distance"] > 5.0


def test_mahalanobis_catches_correlated_anomaly(clock):
    """Mahalanobis should catch anomalies that independent z-scores miss."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    # Traffic with moderate individual z-scores but correlated deviation
    for k in range(10):
        clock.t = 400.0 + k
        # Each metric is slightly elevated, but together they're anomalous
        correlated_flows = [_flow(k * 9 + j, pps=15.0, pkt_size=150) for j in range(9)]
        res = ea.update(1, correlated_flows)

    # Mahalanobis should detect this as anomalous even if individual z-scores are < 2.5
    # The exact threshold depends on the implementation
    assert res["mahalanobis_distance"] > 2.0
