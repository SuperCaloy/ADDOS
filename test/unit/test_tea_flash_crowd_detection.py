"""Test flash crowd detection against TEA's actual detection logic.

Key insight: proto_surge is a LOCAL variable, not in the result dict.
We verify via is_flash_crowd (which depends on proto_surge) and proto_zscore.

Flash crowd definition (entropy_analyzer.py:714):
    is_flash_crowd = (
        volume_anomaly
        and not collapse_anomaly
        and not mechanized_cluster
        and proto_surge
    )
"""
import pytest
import math
import random
from collections import Counter

from backend.pipeline import entropy_analyzer as ea_mod
from backend.pipeline.entropy_analyzer import EntropyAnalyzer


class _FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start
    def monotonic(self) -> float:
        return self.t


@pytest.fixture()
def clock(monkeypatch):
    c = _FakeClock()
    monkeypatch.setattr(ea_mod, "time", c)
    return c


def _flow(seed: int, proto: int = 6, pkt_size: int = 100,
          pps: float = 10.0) -> dict:
    byt = float(pkt_size * max(1, int(pps * 2)))
    return {
        "src_ip": f"10.0.{(seed % 5) + 1}.{(seed % 250) + 1}",
        "packet_count": float(40 + (seed * 7) % 60),
        "byte_count": byt,
        "packet_count_per_second": pps,
        "byte_count_per_second": byt * pps / max(1, 40 + (seed * 7) % 60),
        "ip_proto": proto,
    }


def _normal_flows(k: int) -> list[dict]:
    """Normal web traffic: mostly TCP (80%), some UDP (DNS).
    Creates LOW baseline proto_entropy (~0.503).
    Consistent packet sizes/intensities to avoid false collapse.
    """
    protos = [6, 6, 6, 6, 6, 6, 6, 6, 17]
    return [_flow(k * 9 + j, proto=p, pps=10.0)
            for j, p in enumerate(protos)]


def _flash_crowd_flows(k: int) -> list[dict]:
    """Flash crowd: diverse protocols (TCP + UDP + ICMP), high volume.
    Creates HIGH proto_entropy (~1.585), triggering proto_surge.
    """
    protos = [6, 6, 6, 17, 17, 17, 1, 1, 1]
    pps_values = [25, 28, 30, 22, 26, 35, 20, 24, 32]
    return [_flow(k * 9 + j, proto=p, pps=pps)
            for j, (p, pps) in enumerate(zip(protos, pps_values))]


def _attack_flows(k: int) -> list[dict]:
    """Attack: uniform protocol (all TCP), same size, high pps."""
    return [_flow(k * 9 + j, proto=6, pkt_size=64, pps=50)
            for j in range(9)]


def _learn(ea: EntropyAnalyzer, clock: _FakeClock, intervals: int = 350) -> None:
    for i in range(intervals):
        clock.t = float(i)
        ea.update(1, _normal_flows(i))
    assert ea._global_state.is_learned, "Baselines should be learned"


# === Core Flash Crowd Detection Tests ===


def test_flash_crowd_detected(clock):
    """Flash crowd with diverse protocols should trigger is_flash_crowd."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    # proto_surge is a local variable, not in result dict.
    # Verify via proto_zscore (must be high positive) and is_flash_crowd.
    # Floor (TEA_MIN_STD_FLOOR) caps z-score; check it is positive and above sigma.
    assert res["proto_zscore"] > 20.0, (
        f"proto_zscore should be high (floor-capped), got {res['proto_zscore']}"
    )
    assert res["is_flash_crowd"] is True, (
        f"Should be flash crowd. pps_surge={res['pps_surge']} "
        f"mechanized={res['mechanized_cluster']} proto_z={res['proto_zscore']}"
    )


def test_flash_crowd_volume_anomaly(clock):
    """Flash crowd triggers pps_surge (volume anomaly)."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    assert res["pps_surge"] is True, "pps_surge should be True"


def test_flash_crowd_not_mechanized(clock):
    """Flash crowd should NOT be mechanized_cluster (diverse protocols)."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    assert res["mechanized_cluster"] is False, (
        f"mechanized_cluster should be False, got uniform_share={res['uniform_share']}"
    )


def test_flash_crowd_no_collapse(clock):
    """Flash crowd should NOT have collapse (diverse traffic)."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    # Collapse means size/intensity went DOWN (concentrated traffic).
    # Flash crowd increases volume, so collapse should be False.
    assert res["size_zscore"] > -2.0, (
        f"size_zscore should not be deeply negative (no collapse), got {res['size_zscore']}"
    )


def test_flash_crowd_blocks_mitigation(clock):
    """Flash crowd should block mitigation unless flood prefilter flagged."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    assert ea.should_submit(res, is_flood_prefilter_flagged=False) is False


def test_flash_crowd_with_flood_prefilter_allows_mitigation(clock):
    """Flash crowd + flood prefilter flagged should allow mitigation."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _flash_crowd_flows(k))

    assert ea.should_submit(res, is_flood_prefilter_flagged=True) is True


# === Topology.py Pattern Tests ===


def test_topology_flash_crowd_pattern(clock):
    """Test the actual flash crowd pattern from topology.py."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        flows = [
            _flow(k * 9 + 0, proto=1, pps=25),   # ICMP
            _flow(k * 9 + 1, proto=1, pps=22),   # ICMP
            _flow(k * 9 + 2, proto=6, pps=30),   # TCP
            _flow(k * 9 + 3, proto=6, pps=28),   # TCP
            _flow(k * 9 + 4, proto=17, pps=35),  # UDP
            _flow(k * 9 + 5, proto=17, pps=32),  # UDP
            _flow(k * 9 + 6, proto=17, pps=28),  # UDP
            _flow(k * 9 + 7, proto=6, pps=26),   # TCP
            _flow(k * 9 + 8, proto=6, pps=24),   # TCP
        ]
        res = ea.update(1, flows)

    assert res["is_flash_crowd"] is True, (
        f"Topology flash crowd should be detected. proto_z={res['proto_zscore']} "
        f"pps_surge={res['pps_surge']} mech={res['mechanized_cluster']}"
    )


# === Best Simulation Patterns ===


def test_best_high_volume_diverse_protos(clock):
    """Best pattern: high volume + diverse protocols, no collapse."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        flows = [
            _flow(k * 9 + j, proto=p, pkt_size=120, pps=35.0)
            for j, p in enumerate([6, 17, 1, 6, 17, 1, 6, 17, 1])
        ]
        res = ea.update(1, flows)

    assert res["is_flash_crowd"] is True


def test_best_sudden_spike(clock):
    """Best pattern: sudden volume spike with protocol diversity."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(5):
        clock.t = 400.0 + k
        ea.update(1, _normal_flows(k))

    for k in range(5):
        clock.t = 405.0 + k
        flows = [
            _flow(k * 9 + j, proto=p, pps=random.uniform(40, 60))
            for j, p in enumerate([6, 17, 1, 6, 17, 1, 6, 17, 1])
        ]
        res = ea.update(1, flows)

    assert res["is_flash_crowd"] is True


def test_best_mixed_campaign(clock):
    """Best pattern: mixed campaign with diverse protocols and sizes."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        flows = [
            _flow(k * 9 + 0, proto=6, pkt_size=60, pps=35),
            _flow(k * 9 + 1, proto=6, pkt_size=1200, pps=25),
            _flow(k * 9 + 2, proto=17, pkt_size=100, pps=40),
            _flow(k * 9 + 3, proto=1, pkt_size=64, pps=30),
            _flow(k * 9 + 4, proto=6, pkt_size=80, pps=32),
            _flow(k * 9 + 5, proto=17, pkt_size=200, pps=28),
            _flow(k * 9 + 6, proto=1, pkt_size=64, pps=33),
            _flow(k * 9 + 7, proto=6, pkt_size=100, pps=29),
            _flow(k * 9 + 8, proto=17, pkt_size=150, pps=31),
        ]
        res = ea.update(1, flows)

    assert res["is_flash_crowd"] is True


# === Negative Tests ===


def test_attack_not_flash_crowd(clock):
    """Uniform attack should NOT be flash crowd."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _attack_flows(k))

    # Attack may or may not trigger mechanized_cluster depending on
    # how similar the normal baseline uniform_share is, but it must
    # NOT be classified as flash crowd.
    assert res["is_flash_crowd"] is False, "Attack should not be flash crowd"
    assert res["is_attack_pattern"] is True, "Attack should be detected as attack"


def test_normal_traffic_not_flash_crowd(clock):
    """Normal traffic should NOT be flash crowd."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    for k in range(10):
        clock.t = 400.0 + k
        res = ea.update(1, _normal_flows(k))

    assert res["is_flash_crowd"] is False
