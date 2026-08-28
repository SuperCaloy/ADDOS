"""T31: fallback handling and visible-progress requirements for the runner.

New failing-first tests for behaviors the surviving t23-t30 suite does not
pin (plan sections "Execution requirements", failure-mode rows, RT1/RT2
findings): port-in-use fail-fast, partial-start cleanup, terminal-window
launch with headless subprocess fallback, visible per-stage progress,
teardown ordering with net.stop hang guard, backend-death tolerant
teardown, survivor-aware verdicts, invalid-wave null metrics, and clear
startup timeouts.
"""
import time
import types
from pathlib import Path
from threading import Event

import pytest

from simulation.run_benchmark import (
    StackStartupError,
    build_wave_metrics,
    check_ports_free,
    guarded_net_stop,
    launch_mode,
    recover_display_env,
    start_stack,
    teardown_stack,
    terminal_command,
    wait_for_port,
)
from simulation.verdicts import compute_run_verdict


class FakeProc:
    def __init__(self, name, calls):
        self.name = name
        self.calls = calls
        self.pid = abs(hash(name)) % 10000

    def terminate(self):
        self.calls.append((self.name, "terminate"))

    def kill(self):
        self.calls.append((self.name, "kill"))

    def wait(self, timeout=None):
        self.calls.append((self.name, "wait"))
        return 0


def _fake_topology(order):
    net = types.SimpleNamespace(
        start=lambda: order.append("net.start"),
        get=lambda name: "s0",
        stop=lambda: order.append("net.stop"))
    return types.SimpleNamespace(
        build_star=lambda: (net, ["hosts"], ["s1", "s2"], "dist"),
        net=net,
        _speed_up_reconnect=lambda *a: order.append("_speed_up_reconnect"),
        _assign_attacks=lambda: order.append("_assign_attacks"),
        _print_banner=lambda *a: None,
        _reset_ryu_state=lambda: order.append("_reset_ryu_state"),
        start_server=lambda: order.append("start_server"),
        _warmup_macs=lambda: order.append("_warmup_macs"),
        start_baseline_traffic=lambda: order.append("start_baseline_traffic"),
        _start_restore_poller=lambda: order.append("_start_restore_poller"),
        stop_all_attacks=lambda: order.append("stop_all_attacks"),
        _RESTORE_POLLER_STOP=Event(),
        _BASELINE_WATCHDOG_STOP=Event(),
        _WATCHDOG_SUPPRESS=Event(),
    )


# --- port-in-use fail-fast (failure-mode row 6, minus dead --attach leg) ---

def test_check_ports_free_reports_occupied_ports():
    occupied = check_ports_free((6633, 5000, 8080),
                                connect_probe=lambda p: p == 5000)
    assert occupied == [5000]


def test_start_stack_fails_fast_before_spawning_when_port_occupied():
    spawned = []
    log = []
    with pytest.raises(StackStartupError) as exc:
        start_stack(Path("/tmp/out"), log=log.append,
                    spawn=lambda cmd, lp: spawned.append(cmd),
                    connect_probe=lambda p: True)
    assert "5000" in str(exc.value)
    assert spawned == []


# --- visible per-stage progress ---

def test_start_stack_emits_ordered_stage_progress():
    order, calls = [], []
    procs = {"ryu": FakeProc("ryu", calls), "backend": FakeProc("backend", calls),
             "frontend": FakeProc("frontend", calls)}
    it = iter([procs["ryu"], procs["backend"], procs["frontend"]])
    log = []
    start_stack(Path("/tmp/out"), log=log.append,
                spawn=lambda cmd, lp: next(it),
                connect_probe=lambda p: False,
                wait_port_fn=lambda port, timeout_s, label: None,
                wait_http_fn=lambda url, timeout_s, label: None,
                topology_factory=lambda: _fake_topology(order))
    stages = [m for m in log if m.startswith("[")]
    assert stages[0].startswith("[1/4]") and "Ryu" in stages[0]
    assert any(m.startswith("[2/4]") and "topology" in m.lower() for m in stages)
    assert any(m.startswith("[3/4]") and "backend" in m.lower() for m in stages)
    assert any(m.startswith("[4/4]") and "frontend" in m.lower() for m in stages)


# --- partial-start cleanup (failure-mode row 7 + RT1-M1) ---

def test_start_stack_backend_failure_kills_children_and_cleans_ovs():
    order, calls = [], []
    procs = {"ryu": FakeProc("ryu", calls), "backend": FakeProc("backend", calls)}
    it = iter([procs["ryu"], procs["backend"]])
    cleanups = []

    def boom(url, timeout_s, label):
        raise StackStartupError(f"{label} never became healthy")

    with pytest.raises(StackStartupError):
        start_stack(Path("/tmp/out"), log=lambda m: None,
                    spawn=lambda cmd, lp: next(it),
                    connect_probe=lambda p: False,
                    wait_port_fn=lambda port, timeout_s, label: None,
                    wait_http_fn=boom,
                    topology_factory=lambda: _fake_topology(order),
                    cleanup_fn=lambda cmd: cleanups.append(cmd))
    terminated = [n for n, op in calls if op == "terminate"]
    # reverse start order: backend before ryu
    assert terminated.index("backend") < terminated.index("ryu")
    assert any("mn -c" in c for c in cleanups)


def test_start_stack_replicates_topology_startup_order():
    order, calls = [], []
    procs = {"ryu": FakeProc("ryu", calls), "backend": FakeProc("backend", calls),
             "frontend": FakeProc("frontend", calls)}
    it = iter([procs["ryu"], procs["backend"], procs["frontend"]])
    start_stack(Path("/tmp/out"), log=lambda m: None,
                spawn=lambda cmd, lp: next(it),
                connect_probe=lambda p: False,
                wait_port_fn=lambda port, timeout_s, label: None,
                wait_http_fn=lambda url, timeout_s, label: None,
                topology_factory=lambda: _fake_topology(order),
                sleep_fn=lambda s: None)
    assert order == ["net.start", "_speed_up_reconnect", "_assign_attacks",
                     "_reset_ryu_state", "start_server", "_warmup_macs",
                     "start_baseline_traffic", "_start_restore_poller"]


# --- terminal windows vs headless fallback (requirement 1, RT1-H2) ---

def test_recover_display_env_prefers_own_display():
    assert recover_display_env({"DISPLAY": ":1"})["DISPLAY"] == ":1"


def test_recover_display_env_scans_sudo_user_processes():
    env = recover_display_env(
        {"SUDO_USER": "killua"},
        pid_lister=lambda: [100, 200],
        reader=lambda pid: {"DISPLAY": ":0"} if pid == 200 else {})
    assert env["DISPLAY"] == ":0"


def test_recover_display_env_empty_when_headless():
    assert recover_display_env({}) == {}


def test_launch_mode_falls_back_without_display_or_xterm():
    assert launch_mode({}, which=lambda n: "/usr/bin/xterm")[0] == "subprocess"
    assert launch_mode({"DISPLAY": ":0"}, which=lambda n: None)[0] == "subprocess"
    assert launch_mode({"DISPLAY": ":0"},
                       which=lambda n: "/usr/bin/xterm")[0] == "terminal"


def test_terminal_command_tees_output_to_session_log():
    cmd = terminal_command("python3 -m backend.main", Path("/tmp/o/backend.log"))
    assert "backend.log" in cmd
    assert "tee" in cmd


# --- teardown ordering and hang guards (RT1-M1/M7, R1e, R2e) ---

def test_teardown_sets_events_stops_attacks_sweeps_then_netstop():
    order, calls = [], []
    topo = _fake_topology(order)
    stop_all = topo.stop_all_attacks

    def record_stop():
        order.append(("events_set_before_stop",
                      topo._RESTORE_POLLER_STOP.is_set()
                      and topo._BASELINE_WATCHDOG_STOP.is_set()))
        stop_all()

    topo.stop_all_attacks = record_stop

    def fake_cmd(cmd):
        calls.append(cmd)
        return ""

    errs = teardown_stack(topology_mod=topo, procs=[],
                          cmd_runner=fake_cmd,
                          net_stop_fn=lambda: order.append("net.stop"))
    assert errs == []
    assert order[0] == ("events_set_before_stop", True)
    idx = {name: i for i, name in enumerate(
        o if isinstance(o, str) else o[0] for o in order)}
    assert idx["stop_all_attacks"] < idx["net.stop"]
    assert any("pkill" in c for c in calls)


def test_teardown_survives_stop_all_attacks_failure_when_backend_dead():
    order, calls = [], []
    topo = _fake_topology(order)

    def dead_backend():
        order.append("stop_all_attacks")
        raise ConnectionError("backend is dead")

    topo.stop_all_attacks = dead_backend

    def fake_cmd(cmd):
        calls.append(cmd)
        return ""

    errs = teardown_stack(topology_mod=topo, procs=[],
                          cmd_runner=fake_cmd,
                          net_stop_fn=lambda: order.append("net.stop"))
    assert errs  # the failure is reported, not swallowed silently
    assert "net.stop" in order            # teardown continued
    assert any("pkill" in c for c in calls)  # survivor sweep still ran


def test_guarded_net_stop_falls_back_to_mn_c_on_hang():
    ran = []
    used = guarded_net_stop(lambda: time.sleep(0.3), join_s=0.05,
                            cmd_runner=lambda c: ran.append(c) or "")
    assert used is True
    assert any("mn -c" in c for c in ran)

    ran2 = []
    used2 = guarded_net_stop(lambda: None, join_s=0.05,
                             cmd_runner=lambda c: ran2.append(c) or "")
    assert used2 is False
    assert not any("mn -c" in c for c in ran2)


# --- verdict completeness (RT2-H3) ---

def test_verdict_survivors_at_least_degraded():
    assert compute_run_verdict(hping3_survivors=True) == "DEGRADED"


def test_verdict_quiet_window_survivors_invalidate():
    assert compute_run_verdict(survivors_in_quiet=True) == "INVALID"


# --- invalid-wave metrics are absent, not zero (RT2-H3) ---

def test_build_wave_metrics_marks_invalid_wave_as_null():
    from datetime import datetime
    t0 = datetime(2026, 8, 28, 10, 0, 0)
    t1 = datetime(2026, 8, 28, 10, 10, 0)
    m = build_wave_metrics(
        [{"name": "syn_wave", "ips": ["10.0.0.10"]}],
        [{"name": "syn_wave", "start": t0, "end": t1}],
        {}, invalid_waves={"syn_wave"})
    assert m["syn_wave"]["wave_status"] == "invalid"
    assert m["syn_wave"]["if"] is None


# --- clear startup timeouts ---

def test_wait_for_port_raises_clear_error_on_timeout():
    now = iter([0.0, 0.1, 0.2, 0.3])
    with pytest.raises(StackStartupError) as exc:
        wait_for_port(6633, timeout_s=0.2, connect_probe=lambda p: False,
                      sleep=lambda s: None, now=lambda: next(now))
    assert "6633" in str(exc.value)
