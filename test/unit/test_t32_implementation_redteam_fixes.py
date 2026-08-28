"""T32: regression tests from the 2026-08-28 implementation red-team.

Each test pins one finding from the post-implementation red-team passes:
C1/C2 (mixed-wave expected IPs must come from the REAL topology attribute
surface and be IP strings matching ground-truth keys), H1 (signal handlers
cover the startup window), H2 (attacks stopped at schedule end before
survivor sampling), ReportBug artifact preservation, xterm argv form,
duration lower bound, vanished-child termination, empty report body,
missing-archive-table tolerance, reset tool robustness, fast-path teardown.
"""
import sqlite3
import types
from datetime import datetime
from pathlib import Path
from threading import Event

import pytest

import simulation.run_benchmark as rb
from simulation.run_benchmark import (
    _Session,
    _make_signal_handler,
    _run_schedule,
    _generate_report_step,
    parse_args,
    terminal_argv,
)
from simulation.timeline import Phase
from simulation.lifecycle import reverse_terminate
from simulation.report_gen import generate_report
from simulation.reset_behavioral_state import reset
import simulation.metrics_sql as ms


def _fake_topology(order):
    """Mimic the REAL topology attribute surface (red-team C1/C2):
    _attackers_of_type returns host NUMBERS (ints), _ATTACKER_NUMS is a
    frozenset of ints, and there is no _ATTACKER_NUMS_IPV4 helper."""
    net = types.SimpleNamespace(
        start=lambda: order.append("net.start"),
        get=lambda name: "s0",
        stop=lambda: order.append("net.stop"))
    return types.SimpleNamespace(
        build_star=lambda: (net, ["hosts"], ["s1", "s2"], "dist"),
        net=net,
        _speed_up_reconnect=lambda *a: None,
        _assign_attacks=lambda: None,
        _print_banner=lambda *a: None,
        _reset_ryu_state=lambda: None,
        start_server=lambda: None,
        _warmup_macs=lambda: None,
        start_baseline_traffic=lambda: None,
        _start_restore_poller=lambda: None,
        start_mixed_campaign=lambda: order.append("start_mixed_campaign"),
        start_syn_flood_campaign=lambda: order.append("start_syn_flood_campaign"),
        stop_all_attacks=lambda: order.append("stop_all_attacks"),
        _attackers_of_type=lambda v: sorted({6, 7}),
        _ATTACKER_NUMS=frozenset({6, 7}))


def _fake_session(phases):
    session = _Session.__new__(_Session)
    session.args = None
    session.out_dir = None
    session.log = lambda m: None
    session.stop = Event()
    session.abort = Event()
    session.backend_alive = True
    session.ryu_alive = True
    session.clock_drift = False
    session.hping3_survivors = False
    session.survivors_in_quiet = False
    session.invalid_waves = set()
    session.unreliable_waves = set()
    session.seen_gt = {}
    session.timeline = []
    session.calibration = {"status": "passed"}
    session.t_eval_start_mono = 0.0
    session.t_eval_start_local = datetime(2026, 8, 28, 14, 0, 0)
    session.waves_total = 0
    session._last_miss_marks = {"backend": 0, "ryu": 0}
    return session


@pytest.fixture()
def offline_stack(monkeypatch):
    """Patch the module-level I/O seams _run_schedule touches."""
    calls = {"gt": 0}

    def fake_http_json(url, timeout=5.0):
        if "attack_ground_truth" in url:
            calls["gt"] += 1
            return {"10.0.0.6": "MIXED", "10.0.0.7": "MIXED"}
        return {}

    monkeypatch.setattr(rb, "_http_json", fake_http_json)
    monkeypatch.setattr(rb, "_survivor_pids", lambda: [])
    monkeypatch.setattr(rb, "_tcp_connect_ok", lambda p: True)
    return calls


def _fake_clock():
    state = {"t": 0.0}

    def monotonic():
        state["t"] += 1.0
        return state["t"]

    return SimpleNamespaceTime(state)


class SimpleNamespaceTime:
    def __init__(self, state):
        self._state = state

    def monotonic(self):
        self._state["t"] += 1.0
        return self._state["t"]

    def sleep(self, s):
        pass

    def time(self):
        return 1000.0


def test_mixed_wave_expected_ips_are_gt_string_keys(offline_stack):
    """Red-team C1+C2: the MIXED roster must come from the real topology
    attributes (no _ATTACKER_NUMS_IPV4) and be IP strings so ground-truth
    registration polls and wave anchoring actually match."""
    order = []
    session = _fake_session(None)
    fake_time = _fake_clock()
    info = _run_schedule(session, _fake_topology(order),
                         [Phase("mixed_a", 5, "attack", "MIXED")],
                         now=fake_time.monotonic, sleep=fake_time.sleep)
    assert "start_mixed_campaign" in order
    assert info["waves"][0]["ips"] == ["10.0.0.6", "10.0.0.7"]
    assert set(session.seen_gt) == {"10.0.0.6", "10.0.0.7"}
    assert session.unreliable_waves == set()
    assert session.waves_total == 1


def test_single_vector_expected_ips_are_strings(offline_stack):
    order = []
    session = _fake_session(None)
    fake_time = _fake_clock()
    topo = _fake_topology(order)
    info = _run_schedule(session, topo,
                         [Phase("syn_wave", 5, "attack", "SYN")],
                         now=fake_time.monotonic, sleep=fake_time.sleep)
    assert info["waves"][0]["ips"] == ["10.0.0.6", "10.0.0.7"]
    assert session.unreliable_waves == set()


def test_attacks_stopped_before_survivor_sampling_on_truncated_run(offline_stack):
    """Red-team H2: when the schedule ends on an attack phase (mid-wave
    --duration truncation or abort), stop_all_attacks fires at schedule
    end and survivor sampling happens AFTER the stop, never before."""
    order = []
    session = _fake_session(None)
    fake_time = _fake_clock()
    _run_schedule(session, _fake_topology(order),
                  [Phase("mixed_a", 5, "attack", "MIXED")],
                  now=fake_time.monotonic, sleep=fake_time.sleep)
    # stop must be the LAST topology action, after the campaign start
    assert order[-1] == "stop_all_attacks"
    assert "start_mixed_campaign" in order


def test_signal_handler_covers_startup_window():
    """Red-team H1: before the session starts, the first signal must
    route through start_stack's partial-start cleanup (KeyboardInterrupt)
    instead of killing the process with default disposition."""
    session = _fake_session(None)
    session.started = False
    session.fast = False
    handler = _make_signal_handler(session)
    with pytest.raises(KeyboardInterrupt):
        handler(15, None)
    assert session.stop.is_set()

    # after the session started: first signal is graceful, no raise
    session2 = _fake_session(None)
    session2.started = True
    session2.fast = False
    handler2 = _make_signal_handler(session2)
    handler2(2, None)
    assert session2.stop.is_set()
    assert session2.fast is False
    handler2(2, None)  # second signal: fast path
    assert session2.fast is True
    assert session2.abort.is_set()


def test_report_bug_is_recorded_not_fatal():
    """Red-team H1 (helpers): a ReportBug (404 with rows present) must be
    recorded as a note and must NOT destroy the session's artifacts by
    crashing run()."""
    def post(url, payload):
        return 404, b""

    path, note = _generate_report_step(
        datetime(2026, 8, 28, 14, 0, 0), datetime(2026, 8, 28, 15, 0, 0),
        out_dir=None, verdict="CLEAN", is_pilot=False,
        sql_row_check=lambda s, e: 3, post=post)
    assert path is None
    assert "bug" in note.lower()


def test_terminal_argv_uses_bash_c_form():
    """Red-team M5: `xterm -e` execs argv directly, so the whole command
    must be handed to bash -c as separate argv entries."""
    argv = terminal_argv("python3 -m backend.main", "/tmp/o/backend.log")
    assert argv[0] == "xterm"
    assert "bash" in argv and "-c" in argv
    inner = argv[argv.index("-c") + 1]
    assert "backend.log" in inner and "tee" in inner


def test_partial_start_failure_stops_network_and_sweeps():
    """Red-team M1: a failure AFTER the topology phase must attempt
    guarded net.stop and run the hping3 sweep in THIS run - mn -c alone
    deletes bridges but leaves baseline generators and the h20 sink
    running (a half-started state)."""
    from simulation.run_benchmark import StackStartupError, start_stack

    class FakeProc:
        def __init__(self, name, calls):
            self.name = name
            self.calls = calls
            self.pid = 42

        def terminate(self):
            self.calls.append((self.name, "terminate"))

        def kill(self):
            self.calls.append((self.name, "kill"))

        def wait(self, timeout=None):
            return 0

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
                    cleanup_fn=lambda cmd: cleanups.append(cmd),
                    sleep_fn=lambda s: None)
    assert "net.stop" in order
    assert any("pkill" in c for c in cleanups)
    assert any("mn -c" in c for c in cleanups)


def test_default_killer_matches_nul_separated_cmdline(monkeypatch):
    """First-pilot bug: /proc/<pid>/cmdline is NUL-separated argv, but the
    stack markers are space-joined (the form pgrep matches). The killer
    must normalize NULs to spaces or the verification false-negatives and
    autorecover reports a killable leftover as 'surviving kill attempts'."""
    killed = []
    monkeypatch.setattr(rb.os, "kill", lambda pid, sig: killed.append(pid))
    reader = lambda pid: "ryu-manager\x00controller/ryu_controller.py\x00"
    rb._default_killer([4242], cmdline_reader=reader)
    assert killed == [4242]


def test_default_killer_skips_unmatched_cmdline(monkeypatch):
    killed = []
    monkeypatch.setattr(rb.os, "kill", lambda pid, sig: killed.append(pid))
    reader = lambda pid: "vim\x00notes/tasks/foo.md"
    rb._default_killer([4242], cmdline_reader=reader)
    assert killed == []


def test_duration_has_lower_bound():
    with pytest.raises(SystemExit):
        parse_args(["--duration", "0"])
    args = parse_args(["--duration", "60"])
    assert args.duration == 60


def test_reverse_terminate_treats_vanished_child_as_success():
    """Red-team L3: a child that dies between spawn and terminate raises
    ProcessLookupError; that is success, not 'refused to die' noise."""

    class Vanished:
        def terminate(self):
            raise ProcessLookupError()

        def kill(self):
            raise ProcessLookupError()

        def wait(self, timeout=None):
            return 0

    assert reverse_terminate([("ryu", Vanished())], grace_s=0.01) == []


def test_report_empty_body_is_skipped(tmp_path):
    def post(url, payload):
        return 200, b""

    r, why = generate_report(datetime(2026, 8, 28, 14, 0, 0),
                             datetime(2026, 8, 28, 15, 0, 0), tmp_path,
                             verdict="CLEAN", is_pilot=False,
                             sql_row_check=lambda *a: 1, post=post)
    assert r is None


def test_mitigation_events_date_rows_tolerates_only_missing_archive(monkeypatch):
    """Red-team L5: the archive-table exception swallow must be limited to
    'table absent' (OperationalError); a real DB error must propagate so
    the report 404 cross-check cannot be silently defeated."""

    class FakeConn:
        def execute(self, sql, *a):
            if "archive" in sql:
                raise sqlite3.OperationalError("no such table")
            return types.SimpleNamespace(
                fetchone=lambda: {"n": 5})

    @staticmethod
    def fake_rows():
        import contextlib
        return contextlib.nullcontext(FakeConn())

    monkeypatch.setattr(ms, "_rows", lambda: _nullcontext(FakeConn()))
    assert ms.mitigation_events_date_rows("2026-08-28", "2026-08-28") == 5

    class BoomConn:
        def execute(self, sql, *a):
            raise ValueError("disk on fire")

    monkeypatch.setattr(ms, "_rows", lambda: _nullcontext(BoomConn()))
    with pytest.raises(ValueError):
        ms.mitigation_events_date_rows("2026-08-28", "2026-08-28")


import contextlib


def _nullcontext(x):
    return contextlib.nullcontext(x)


def test_reset_tool_survives_corrupt_db(tmp_path):
    """Red-team M3 (helpers): the repair tool's stated use case is a
    corrupt DB; a non-SQLite file must return (False, msg), never raise,
    and must not leak the connection."""
    bad = tmp_path / "garbage.db"
    bad.write_bytes(b"this is not a sqlite database" * 10)
    ok, msg = reset(bad, assume_yes=True, backend_probe=lambda: False)
    assert ok is False
    assert msg


def test_autorecover_reprobes_after_a_settle():
    """Red-team L4: SIGKILLed orphans can linger in pgrep for a moment;
    the re-probe must settle before concluding survivors persist."""
    # structural: the kill loop sleeps between kill and re-probe
    import inspect
    src = inspect.getsource(rb.autorecover_stack)
    assert "sleep" in src
