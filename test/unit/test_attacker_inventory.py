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
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22}
    assert set(topo._ATTACKER_POOL) == set(topo._ATTACKER_NUMS)


def test_pairwise_disjoint_full_coverage():
    a, l = topo._ATTACKER_NUMS, topo._LEGIT_NUMS
    assert not (a & l)
    assert set(a | l | {20, 21}) == set(range(1, 23))


def test_variants_in_lockstep_with_active_set():
    assert set(topo._ATTACKER_VARIANTS) == set(topo._ATTACKER_NUMS)
    assert set(topo._STRESS_CMDS) == set(topo._ATTACKER_NUMS)
    assert set(topo._ATTACKER_START_DELAYS) == set(topo._ATTACKER_NUMS)


def test_repurposed_variants():
    atype16, flags16 = topo._ATTACKER_VARIANTS[16][0], topo._ATTACKER_VARIANTS[16][1]
    atype19, flags19 = topo._ATTACKER_VARIANTS[19][0], topo._ATTACKER_VARIANTS[19][1]
    atype22, flags22 = topo._ATTACKER_VARIANTS[22][0], topo._ATTACKER_VARIANTS[22][1]
    assert atype16 == "SYN" and "-S -p 5432" in flags16
    assert atype19 == "SYN" and "-S -p 25" in flags19   # h19 attacks like h23
    assert atype22 == "SYN" and "-S -p 3389" in flags22


def test_balanced_mix():
    types_ = [t[0] for t in topo._ATTACKER_VARIANTS.values()]
    assert types_.count("SYN") == 5
    assert types_.count("UDP") == 5
    assert types_.count("ICMP") == 5


def test_campaign_rosters_are_active():
    # Full-roster guardrail (2026-08-27): single-vector campaigns must launch
    # EVERY attacker assigned to that type, not a hardcoded subset.
    full = {
        "SYN": {10, 16, 18, 19, 22},
        "ICMP": {11, 12, 13, 14, 15},
        "UDP": {6, 7, 8, 9, 17},
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
    assert 'def launch_udp_flood(attacker_name="h7")' in src
    assert 'def launch_udp_flood_sustained(attacker_name="h7")' in src
    assert 'attacker_name="h16"' not in src
    # h16 is SYN now; nothing may still advertise it as the UDP default
    assert "pkts, h16" not in src


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
    # Aggressiveness bump (2026-08-28): every UDP/ICMP attacker floods with
    # exactly 1024B payloads. Bigger bytes per packet = higher bandwidth with
    # NO extra packet rate, so attack CPU/lag is unchanged. 1024 stays inside
    # the frozen model's training range (<=800B was old; 1024 is the safe cap).
    for num, (atype, flags, _, _) in topo._ATTACKER_VARIANTS.items():
        if atype in ("UDP", "ICMP"):
            assert "--data 1024" in flags, (num, flags)
        else:
            assert "--data" not in flags, (num, flags)
