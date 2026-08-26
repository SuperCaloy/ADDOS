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
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 22, 23}
    assert set(topo._RETIRED_NUMS) == {19, 24, 25, 26, 27}
    assert set(topo._ATTACKER_POOL) == topo._ATTACKER_NUMS | topo._RETIRED_NUMS


def test_pairwise_disjoint_full_coverage():
    a, l, r = topo._ATTACKER_NUMS, topo._LEGIT_NUMS, topo._RETIRED_NUMS
    assert not (a & l) and not (a & r) and not (l & r)
    assert set(a | l | r | {20, 21}) == set(range(1, 28))


def test_variants_in_lockstep_with_active_set():
    assert set(topo._ATTACKER_VARIANTS) == set(topo._ATTACKER_NUMS)
    assert set(topo._STRESS_CMDS) == set(topo._ATTACKER_NUMS)
    assert set(topo._ATTACKER_START_DELAYS) == set(topo._ATTACKER_NUMS)


def test_repurposed_variants():
    atype16, flags16 = topo._ATTACKER_VARIANTS[16][0], topo._ATTACKER_VARIANTS[16][1]
    atype22, flags22 = topo._ATTACKER_VARIANTS[22][0], topo._ATTACKER_VARIANTS[22][1]
    assert atype16 == "SYN" and "-S -p 5432" in flags16
    assert atype22 == "SYN" and "-S -p 3389" in flags22


def test_balanced_mix():
    types_ = [t[0] for t in topo._ATTACKER_VARIANTS.values()]
    assert types_.count("SYN") == 5
    assert types_.count("UDP") == 5
    assert types_.count("ICMP") == 5


def test_campaign_rosters_are_active():
    assert {10, 18, 22} <= set(topo._ATTACKER_NUMS)
    assert {11, 12, 13} <= set(topo._ATTACKER_NUMS)
    assert {6, 7, 8} <= set(topo._ATTACKER_NUMS)


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
