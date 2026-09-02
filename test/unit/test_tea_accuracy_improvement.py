# test/unit/test_tea_accuracy_improvement.py
"""Test that Mahalanobis + temporal entropy improves detection accuracy."""
import pytest
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


def _stable_flow(seed, proto=6, pkt_size=100, pps=10.0):
    byt = float(pkt_size * max(1, int(pps * 2)))
    return {
        "src_ip": f"10.0.{(seed % 5) + 1}.{(seed % 250) + 1}",
        "packet_count": 70.0,
        "byte_count": byt,
        "packet_count_per_second": pps,
        "byte_count_per_second": byt * pps / 70.0,
        "ip_proto": proto,
    }


def _normal_flows(k):
    protos = [6, 6, 6, 6, 6, 6, 6, 6, 17]
    return [_stable_flow(k * 9 + j, proto=p, pps=10.0) for j, p in enumerate(protos)]


def _learn(ea, clock):
    for i in range(350):
        clock.t = float(i)
        ea.update(1, _normal_flows(i))


def test_flash_crowd_detected_by_mahalanobis(clock):
    """Flash crowd should be detected by Mahalanobis distance."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        # Diverse protocols, high volume - flash crowd pattern
        protos = [6, 6, 6, 17, 17, 17, 1, 1, 1]
        pps_vals = [25, 28, 30, 22, 26, 35, 20, 24, 32]
        flows = [_flow(k * 9 + j, proto=p, pps=pps)
                 for j, (p, pps) in enumerate(zip(protos, pps_vals))]
        res = ea.update(1, flows)

    # Mahalanobis should detect this even if individual z-scores don't
    assert res["mahalanobis_distance"] > 3.0


def test_low_rate_attack_detected_by_temporal(clock):
    """Low-rate attack with periodic timing should be detected by temporal entropy."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    # Low-rate but periodic attack (machine-like timing)
    for k in range(10):
        clock.t = 400.0 + k
        # All same protocol, same size, low but steady pps
        periodic_flows = [_flow(k * 9 + j, proto=6, pkt_size=64, pps=5.0) for j in range(9)]
        res = ea.update(1, periodic_flows)

    # Should detect via temporal entropy (periodic pattern)
    assert res["temporal_entropy"] < 2.0  # Low entropy = periodic


def test_no_false_positive_on_normal_traffic(clock):
    """Normal traffic should not trigger false positives."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    false_positives = 0
    for k in range(50):
        clock.t = 400.0 + k
        res = ea.update(1, _normal_flows(k))
        if res.get("is_attack_pattern"):
            false_positives += 1

    assert false_positives == 0
