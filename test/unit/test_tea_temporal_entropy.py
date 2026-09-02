"""Test temporal entropy dimension (inter-arrival time patterns)."""
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


def _normal_flows(k):
    protos = [6, 6, 6, 6, 6, 6, 6, 6, 17]
    return [_flow(k * 9 + j, proto=p, pps=10.0) for j, p in enumerate(protos)]


def _learn(ea, clock):
    for i in range(350):
        clock.t = float(i)
        ea.update(1, _normal_flows(i))


def test_temporal_entropy_in_snapshot(clock):
    """Snapshot should contain temporal_entropy."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)
    clock.t = 400.0
    res = ea.update(1, _normal_flows(0))
    assert "temporal_entropy" in res
    assert isinstance(res["temporal_entropy"], float)


def test_temporal_baseline_learned(clock):
    """Temporal baseline should learn during warmup."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)
    assert ea._global_state.temporal_base.is_learned


def test_bursty_traffic_different_entropy(clock):
    """Bursty traffic should have different temporal entropy than steady."""
    ea = EntropyAnalyzer()
    _learn(ea, clock)

    # Steady traffic (same pps)
    clock.t = 400.0
    steady = ea.update(1, _normal_flows(0))
    steady_ent = steady["temporal_entropy"]

    # Bursty traffic (varying pps)
    clock.t = 401.0
    bursty_flows = [_flow(i, pps=5.0 if i % 2 else 20.0) for i in range(9)]
    bursty = ea.update(1, bursty_flows)
    bursty_ent = bursty["temporal_entropy"]

    # They should differ (bursty has different inter-arrival pattern)
    assert steady_ent != bursty_ent
