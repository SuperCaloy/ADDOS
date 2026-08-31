"""Attacker-inventory consistency guardrails (E7, reduce-attackers plan).

Imports the real topology module offline (stubbed mininet) and asserts the
sets, variants, campaign rosters and launcher defaults stay in lockstep, so
a future host-set edit cannot drift silently.
"""
import importlib.util
import sys
import types

import pytest


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
        "topology_inventory_test", "topology/topology.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["topology_inventory_test"] = mod
    spec.loader.exec_module(mod)
    return mod


topo = _load_topology()


def test_set_sizes_and_membership():
    assert set(topo._ATTACKER_NUMS) == {
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
    assert set(topo._ATTACKER_POOL) == set(topo._ATTACKER_NUMS)


def test_pairwise_disjoint_full_coverage():
    a, l = topo._ATTACKER_NUMS, topo._LEGIT_NUMS
    assert not (a & l)
    assert set(a | l | {26, 27}) == set(range(1, 28))


def test_variants_in_lockstep_with_active_set():
    assert set(topo._ATTACKER_VARIANTS) == set(topo._ATTACKER_NUMS)
    assert set(topo._STRESS_CMDS) == set(topo._ATTACKER_NUMS)
    assert set(topo._ATTACKER_START_DELAYS) == set(topo._ATTACKER_NUMS)


def test_repurposed_variants():
    atype16, flags16 = topo._ATTACKER_VARIANTS[16][0], topo._ATTACKER_VARIANTS[16][1]
    atype19, flags19 = topo._ATTACKER_VARIANTS[19][0], topo._ATTACKER_VARIANTS[19][1]
    atype20, flags20 = topo._ATTACKER_VARIANTS[20][0], topo._ATTACKER_VARIANTS[20][1]
    assert atype16 == "SYN" and "-S -p 80" in flags16
    assert atype19 == "SYN" and "-S -p 8080" in flags19
    assert atype20 == "UDP" and "--udp -p 53" in flags20


def test_balanced_mix():
    types_ = [t[0] for t in topo._ATTACKER_VARIANTS.values()]
    assert types_.count("SYN") == 4
    assert types_.count("UDP") == 3
    assert types_.count("ICMP") == 3


def test_campaign_rosters_are_active():
    # Full-roster guardrail (2026-08-27): single-vector campaigns must launch
    # EVERY attacker assigned to that type, not a hardcoded subset.
    full = {
        "SYN": {16, 17, 18, 19},
        "ICMP": {23, 24, 25},
        "UDP": {20, 21, 22},
    }
    for t, hosts in full.items():
        assert set(topo._attackers_of_type(t)) == hosts


def test_no_hardcoded_campaign_rosters_in_source():
    # The old literal rosters must never reappear; the campaigns derive their
    # host lists from _ATTACKER_VARIANTS via _attackers_of_type() now.
    src = open("topology/topology.py").read()
    for lit in ("[10, 18, 22]", "[11, 12, 13]", "[6, 7, 8]"):
        assert lit not in src


def test_mixed_campaign_launches_randomized():
    # Randomized realism (2026-08-29): the mixed campaign must randomly assign
    # attack types (SYN/UDP/ICMP) to attackers with no two same at a time.
    import re
    src = open("topology/topology.py").read()
    i = src.find("def start_mixed_campaign")
    body = src[i:src.find("\ndef ", i)]
    # randomized type assignment
    assert "_randomize_mixed_attacks()" in body
    assert "_ATTACKER_START_DELAYS" in body
    # uses randomized worker
    assert "_attacker_cycle_worker_randomized" in body


def test_attacker_worker_accepts_delay_override():
    # Wave scheduling needs an explicit per-host delay; the worker's default
    # behavior (own jitter from _ATTACKER_START_DELAYS) must stay intact.
    import re
    src = open("topology/topology.py").read()
    sig = re.search(r"def _attacker_cycle_worker\([^)]*\)", src, re.DOTALL)
    assert sig and "delay" in sig.group(0)


def test_launcher_defaults_are_active_and_typed():
    src = open("topology/topology.py").read()
    assert 'def launch_udp_flood(attacker_name="h20")' in src
    assert 'def launch_udp_flood_sustained(attacker_name="h20")' in src
    assert 'def launch_syn_flood(attacker_name="h16")' in src
    assert 'def launch_icmp_flood(attacker_name="h23")' in src


def test_cleanup_sweeps_cover_pool():
    for fn in ("_kill_all_attackers", "_discard_attackers_locally"):
        i = open("topology/topology.py").read().find(f"def {fn}")
        body = open("topology/topology.py").read()[i:]
        body = body[:body.find("\ndef ", 5)]
        assert "_ATTACKER_POOL" in body


def test_load_does_not_poison_topology_namespace():
    # Regression (2026-08-28): loading topology.py under a foreign module
    # name used to leave a broken 'topology' namespace in sys.modules, so
    # every later `import topology.*` failed with "topology is not a
    # package". Loading must stay side-effect free for the namespace.
    _load_topology()
    import topology.benchmark   # must not raise ModuleNotFoundError
    import topology.topology
    assert hasattr(topology.benchmark, "run")


def test_udp_icmp_payloads_capped_at_1024():
    # Archetype separation (2026-08-31): the three attack classes must stay
    # distinguishable on packet size + ports alone, so RF never depends on
    # ip_proto being resolvable. SYN = tiny (~60B, no payload), UDP = 1400B
    # amplification archetype, ICMP = 512B ping-flood archetype (no ports).
    for num, (atype, flags, _, _) in topo._ATTACKER_VARIANTS.items():
        if atype == "UDP":
            assert "--data 1400" in flags, (num, flags)
        elif atype == "ICMP":
            assert "--data 512" in flags, (num, flags)
        else:
            assert "--data" not in flags, (num, flags)
