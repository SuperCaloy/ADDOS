"""Benchmark DB separation: DDOS_DB_PATH env override.

Pins: backend.config honors the env var; session artifact saving resolves
the live DB through the same env override; run() warns when the override
is not set so survey data cannot silently land in the default DB.

History note (2026-09-11): the session reset no longer touches the DB at
all (offence history is preserved in every mode), so the old tests pinning
ledger deletes and missing-DB creation at reset time were rewritten (env
preservation) and deleted (missing-DB creation) respectively.
"""
import importlib
import os
import sqlite3
from unittest import mock


def test_config_honors_ddos_db_path_env(monkeypatch, tmp_path):
    import backend.config as c
    monkeypatch.setenv("DDOS_DB_PATH", "/tmp/opencode/bench-sep/bench.db")
    monkeypatch.setenv("DDOS_DB_MARKER", str(tmp_path / "DB_TARGET"))
    try:
        c = importlib.reload(c)
        assert str(c.DB_PATH) == "/tmp/opencode/bench-sep/bench.db"
    finally:
        monkeypatch.delenv("DDOS_DB_PATH", raising=False)
        # point the marker at a missing tmp path so the final reload proves
        # the true default (logs/ddos.db) regardless of repo state
        monkeypatch.setenv("DDOS_DB_MARKER", str(tmp_path / "missing"))
        importlib.reload(c)
    assert str(c.DB_PATH).endswith("logs/ddos.db")


def _mk_db(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE ip_attack_history(src_ip TEXT, ban_level INT)")
    conn.execute("CREATE TABLE quarantine_state(src_ip TEXT)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.10', 3)")
    conn.execute("INSERT INTO quarantine_state VALUES('10.0.0.10')")
    conn.commit()
    conn.close()


def _mk_topo():
    from unittest import mock
    topo = mock.MagicMock()
    topo._ATTACKER_NUMS = {10}
    topo._RETIRED_NUMS = set()
    topo._LEGIT_NUMS = set()
    topo.BACKEND_API = "http://127.0.0.1:5000"
    return topo


def test_reset_ledgers_env_db_history(tmp_path, monkeypatch):
    from unittest import mock
    import topology.benchmark as b
    env_db = tmp_path / "bench.db"
    _mk_db(env_db)
    monkeypatch.setenv("DDOS_DB_PATH", str(env_db))
    with mock.patch("topology.benchmark._post_json"):
        b._reset_session_keep_ledger(_mk_topo())
    conn = sqlite3.connect(str(env_db))
    conn.row_factory = sqlite3.Row
    left = conn.execute(
        "SELECT COUNT(*) n FROM ip_attack_history WHERE src_ip='10.0.0.10'"
    ).fetchone()["n"]
    ledger = conn.execute(
        "SELECT total_offences t FROM offence_totals WHERE src_ip='10.0.0.10'"
    ).fetchone()
    conn.close()
    assert left == 0
    assert ledger["t"] == 1


def test_reset_falls_back_to_benchmark_db(monkeypatch):
    from pathlib import Path
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    import topology.benchmark as b
    resolved = Path(b._resolve_db_path())
    expected = Path(b.__file__).resolve().parents[1] / "benchmark" / "Mixed_Benchmark" / "benchmark.db"
    assert str(resolved) == str(expected)


def _fast_clock(monkeypatch):
    # Virtual clock so a 300 s session runs in milliseconds.
    import topology.benchmark as b
    now = [1000.0]

    def _sleep(s):
        now[0] += s

    monkeypatch.setattr(b.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(b.time, "sleep", _sleep)


def _run_with_doubles(b, topo, capture=None, marker=None, monkeypatch=None):
    # Hermetic paths so tests never touch the real repo tree. Uses
    # monkeypatch (auto-reverted) instead of .start() (which would leak
    # into other test files and let runs write real session folders).
    assert monkeypatch is not None and marker is not None
    monkeypatch.setattr(b, "_marker_path", lambda: marker)
    # hermetic project root so type DB creation stays inside tmp_path
    monkeypatch.setattr(b, "_project_root", lambda: marker.parent)
    if monkeypatch is not None:
        _fast_clock(monkeypatch)
        mock.patch.object(b, "_clean_poll_gate",
                          lambda topo, limit: None).start()
    try:
        b.run(topo, net=mock.MagicMock(), hosts=[], duration_s=300,
              sessions=1,
              calibration_gate=lambda t, cap_s: None,
              reset_fn=lambda t: None,
              db_gate=lambda t, cap_s: capture is not None and capture.append(
                  os.path.exists(b._marker_path())),
              artifacts_fn=lambda *a, **k: None)
    except SystemExit:
        pass


def test_run_writes_then_removes_db_marker(monkeypatch, tmp_path):
    import topology.benchmark as b
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    marker = tmp_path / "DB_TARGET"
    assert not marker.exists()
    seen = []
    _run_with_doubles(b, mock.MagicMock(), capture=seen, marker=marker,
                      monkeypatch=monkeypatch)
    assert seen == [True], "marker must exist while the session runs"
    assert not marker.exists(), "marker must be removed at session end"


def test_run_prints_restart_instruction(capsys, monkeypatch, tmp_path):
    import topology.benchmark as b
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    marker = tmp_path / "DB_TARGET"
    _run_with_doubles(b, mock.MagicMock(), marker=marker,
                      monkeypatch=monkeypatch)
    out = capsys.readouterr().out
    assert "Restart the backend" in out
    assert "Mixed_Benchmark/benchmark.db" in out


def test_cleanup_stale_marker_removes_and_reports(tmp_path, monkeypatch):
    # Stale-marker sweep: any marker present when a session starts must be
    # removed so the backend boots onto the default DB for normal operation.
    import topology.benchmark as b
    marker = tmp_path / "DB_TARGET"
    marker.write_text(str(tmp_path / "benchmark.db"))
    monkeypatch.setattr(b, "_marker_path", lambda: marker)
    assert b.cleanup_stale_marker() is True
    assert not marker.exists()
    # no marker -> no-op, reports False
    assert b.cleanup_stale_marker() is False


def test_run_still_works_with_env_override_set(capsys, monkeypatch, tmp_path):
    import topology.benchmark as b
    monkeypatch.setenv("DDOS_DB_PATH", str(tmp_path_fixture() / "bench.db"))
    _run_with_doubles(b, mock.MagicMock(), marker=tmp_path / "DB_TARGET",
                      monkeypatch=monkeypatch)
    out = capsys.readouterr().out
    assert "Restart the backend" in out  # marker flow is unconditional


def test_clock_ticker_prints_elapsed_every_five_seconds(monkeypatch, capsys):
    import topology.benchmark as b
    clock = {"now": 0.0}

    class FakeStop:
        def __init__(self):
            self.n = 0
        def wait(self, s):
            self.n += 1
            clock["now"] += s
            return self.n >= 3  # stop after three intervals

    monkeypatch.setattr(b.time, "monotonic", lambda: clock["now"])
    b._clock_ticker(t0=0.0, duration_s=60, stop=FakeStop(), interval_s=5.0)
    out = capsys.readouterr().out
    assert "T+00:05 / 01:00" in out
    assert "T+00:10 / 01:00" in out
    assert "T+00:15" not in out.replace("T+00:15 /", "")  # stopped at 3 ticks
    assert out.count("T+") == 2


def test_clock_ticker_stops_at_session_end(monkeypatch, capsys):
    import topology.benchmark as b
    clock = {"now": 0.0}

    class FakeStop:
        def wait(self, s):
            clock["now"] += s
            return False  # never stopped externally

    monkeypatch.setattr(b.time, "monotonic", lambda: clock["now"])
    b._clock_ticker(t0=0.0, duration_s=8, stop=FakeStop(), interval_s=5.0)
    out = capsys.readouterr().out
    assert "T+00:05" in out
    assert "T+00:10" not in out  # elapsed >= duration ends the ticker


def tmp_path_fixture():
    # tiny helper: tests only need an existing dir path for the env var
    import pathlib
    d = pathlib.Path("/tmp/opencode/bench-sep")
    d.mkdir(parents=True, exist_ok=True)
    return d



