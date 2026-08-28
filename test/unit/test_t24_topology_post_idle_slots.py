"""T24: post-idle slot selection must stay inside the host's trained set.

P6 of the benign-hour-drift-false-positive plan: after an idle window a
benign host used to be reassigned to any protocol slot in the full pool,
letting h2
(trained pure-TCP) or h5 (trained pure-ICMP) emit a foreign protocol and
breach the per-host signature the frozen model treats as normal.
"""
import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_topology():
    mn = types.ModuleType("mininet")
    for sub in ("log", "net", "node", "cli", "link"):
        m = types.ModuleType(f"mininet.{sub}")
        if sub == "log":
            m.info = lambda *a, **k: None
            m.setLogLevel = lambda *a, **k: None
        elif sub == "net":
            m.Mininet = object
        elif sub == "node":
            m.RemoteController = object
            m.OVSKernelSwitch = object
        elif sub == "cli":
            m.CLI = object
        elif sub == "link":
            m.Link = object
        sys.modules.setdefault(f"mininet.{sub}", m)
        setattr(mn, sub, m)
    sys.modules.setdefault("mininet", mn)

    spec = importlib.util.spec_from_file_location(
        "topology_post_idle_test", str(REPO_ROOT / "topology" / "topology.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["topology_post_idle_test"] = mod
    spec.loader.exec_module(mod)
    return mod


topo = _load_topology()


def test_post_idle_slots_match_trained_host_slots():
    for num, trained in topo._HOST_SLOTS.items():
        assert topo._post_idle_slots(num) == list(trained)


def test_post_idle_slots_unknown_host_falls_back_to_icmp():
    assert topo._post_idle_slots(99) == [("icmp_cont", 1)]


def test_h2_stays_pure_tcp_and_h5_pure_icmp_after_idle():
    assert all(slot_type == "tcp"
               for slot_type, _ in topo._post_idle_slots(2))
    assert all(slot_type == "icmp_cont"
               for slot_type, _ in topo._post_idle_slots(5))
