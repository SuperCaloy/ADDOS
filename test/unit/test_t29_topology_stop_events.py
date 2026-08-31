"""T29: topology teardown hardening for the benchmark runner.

R1e: restore-poller and baseline-watchdog loops gain module-level stop
Events (set FIRST in runner teardown, otherwise the poller calls
restore_baseline_for_ip against a torn-down hosts list).
R2a (BLOCKING): watchdog suppression flag so the watchdog cannot resurrect
baseline mid-flash-crowd and corrupt the FP probe.
"""
import threading

import pytest

from test_t29_helpers import load_topology_stubbed

topo = load_topology_stubbed("topology_stop_events_test")


@pytest.fixture(autouse=True)
def _clear_events():
    topo._RESTORE_POLLER_STOP.clear()
    topo._BASELINE_WATCHDOG_STOP.clear()
    topo._WATCHDOG_SUPPRESS.clear()
    yield
    topo._RESTORE_POLLER_STOP.set()
    topo._BASELINE_WATCHDOG_STOP.set()
    topo._WATCHDOG_SUPPRESS.clear()


class _FakeHost:
    def __init__(self, num):
        self.name = f"h{num}"
        self.IP = lambda: f"10.0.0.{num}"


def _seed_watchdog_state(monkeypatch, hosts):
    calls = []
    monkeypatch.setattr(topo, "hosts", hosts)
    monkeypatch.setattr(topo, "_baseline_threads", {})
    monkeypatch.setattr(topo, "restore_baseline_for_ip",
                        lambda ip: calls.append(ip) or True)
    return calls


def test_stop_events_exist_as_module_level():
    assert isinstance(topo._RESTORE_POLLER_STOP, threading.Event)
    assert isinstance(topo._BASELINE_WATCHDOG_STOP, threading.Event)
    assert isinstance(topo._WATCHDOG_SUPPRESS, threading.Event)


def test_baseline_watchdog_loop_exits_on_stop_event():
    topo._BASELINE_WATCHDOG_STOP.set()
    t = threading.Thread(target=topo._baseline_watchdog_loop, daemon=True)
    t.start()
    t.join(timeout=2.0)
    assert not t.is_alive()


def test_restore_poller_loop_exits_on_stop_event():
    topo._RESTORE_POLLER_STOP.set()
    t = threading.Thread(target=topo._restore_poller_loop, daemon=True)
    t.start()
    t.join(timeout=2.0)
    assert not t.is_alive()


def test_watchdog_tick_resurrects_dead_baseline_when_not_suppressed(monkeypatch):
    calls = _seed_watchdog_state(monkeypatch, [_FakeHost(1)])
    topo._watchdog_tick()
    assert calls == ["10.0.0.1"]


def test_watchdog_tick_suppressed_during_flash_crowd(monkeypatch):
    calls = _seed_watchdog_state(monkeypatch, [_FakeHost(1)])
    topo._WATCHDOG_SUPPRESS.set()
    topo._watchdog_tick()
    assert calls == []


def test_watchdog_tick_ignores_non_legit_hosts(monkeypatch):
    calls = _seed_watchdog_state(monkeypatch, [_FakeHost(16)])
    topo._watchdog_tick()
    assert calls == []


def test_flash_crowd_worker_sets_and_clears_suppression():
    src = open("topology/topology.py").read()
    i = src.find("def _flash_crowd_worker")
    body = src[i:src.find("\ndef ", i)]
    assert "_WATCHDOG_SUPPRESS.set()" in body
    # cleared in a finally so a worker crash cannot kill the watchdog forever
    assert "finally:" in body and "_WATCHDOG_SUPPRESS.clear()" in body


def test_start_restore_poller_clears_stop_events():
    src = open("topology/topology.py").read()
    i = src.find("def _start_restore_poller")
    body = src[i:src.find("\ndef ", i)]
    assert ".clear()" in body
