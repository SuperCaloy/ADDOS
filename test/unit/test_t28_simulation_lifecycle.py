"""T28: runner lifecycle helpers (simulation.lifecycle).

Pins: DB trio move-aside (R5a), sqlite backup-API archive (never raw copy),
reverse-order child termination with kill fallback, GLOBAL pgrep command
form (R1b shared PID namespace), manifest/config-knob dumps (R4a).
"""
import sqlite3
import subprocess

import pytest

from simulation.lifecycle import (
    build_manifest,
    config_knob_dump,
    move_db_trio,
    pgrep_cmd,
    pkill_cmd,
    platform_spec,
    reverse_terminate,
    archive_db_backup,
)


class _FakeProc:
    def __init__(self, behave="exit"):
        self.calls = []
        self.behave = behave

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append("wait")
        if self.behave == "exit" or "kill" in self.calls:
            return 0
        raise subprocess.TimeoutExpired(self, timeout)


def test_pgrep_and_pkill_are_global_not_host_scoped():
    assert pgrep_cmd("hping3") == ["pgrep", "-x", "hping3"]
    assert pkill_cmd("hping3") == ["pkill", "-9", "-x", "hping3"]
    for cmd in (pgrep_cmd("hping3"), pkill_cmd("ping")):
        assert "nsenter" not in cmd


def test_reverse_terminate_terminates_in_reverse_start_order():
    procs = [("ryu", _FakeProc()), ("backend", _FakeProc()), ("frontend", _FakeProc())]
    errs = reverse_terminate(procs, grace_s=0.01)
    assert errs == []
    assert procs[2][1].calls[0] == "terminate"
    assert procs[0][1].calls[0] == "terminate"


def test_reverse_terminate_kills_stragglers():
    slow = _FakeProc(behave="hang")
    procs = [("ryu", _FakeProc()), ("backend", slow)]
    errs = reverse_terminate(procs, grace_s=0.01)
    assert errs == []
    assert "kill" in slow.calls


def test_move_db_trio_moves_all_three_files(tmp_path):
    src, dest = tmp_path / "logs", tmp_path / "run"
    src.mkdir(); dest.mkdir()
    for n in ("ddos.db", "ddos.db-wal", "ddos.db-shm"):
        (src / n).write_text("x")
    moved = move_db_trio(src, dest)
    assert moved == ["ddos.db", "ddos.db-wal", "ddos.db-shm"]
    assert (dest / "ddos.db").exists()
    assert not (src / "ddos.db-wal").exists()


def test_move_db_trio_tolerates_missing_sidecars(tmp_path):
    src, dest = tmp_path / "logs", tmp_path / "run"
    src.mkdir(); dest.mkdir()
    (src / "ddos.db").write_text("x")
    moved = move_db_trio(src, dest)
    assert moved == ["ddos.db"]


def test_archive_db_backup_uses_backup_api(tmp_path):
    src = tmp_path / "ddos.db"
    conn = sqlite3.connect(src)
    conn.execute("CREATE TABLE t (a INTEGER)")
    conn.execute("INSERT INTO t VALUES (42)")
    conn.commit()
    dest = tmp_path / "archived.db"
    archive_db_backup(src, dest)
    conn.close()
    check = sqlite3.connect(dest)
    assert check.execute("SELECT a FROM t").fetchone()[0] == 42
    check.close()


def test_config_knob_dump_contains_gate_knobs():
    knobs = config_knob_dump()
    for key in ("ML_ENABLED", "SIMULATION_MODE", "RF_BATCH_ENABLED",
                "IF_BATCH_ENABLED", "ADMISSION_CONTROL_ENABLED",
                "WORKER_ADMISSION_DEPTH", "TEA_MIN_FLOWS_PER_INTERVAL"):
        assert key in knobs


def test_platform_spec_fields():
    spec = platform_spec()
    assert "platform" in spec and "python" in spec and "kernel" in spec


def test_build_manifest_records_both_clocks_and_verdict():
    m = build_manifest(
        seed=1, pids={"ryu": 10, "backend": 11}, t_eval_start_mono=123.456,
        t_eval_start_local="2026-08-28 14:00:00", duration_s=3600,
        verdict="CLEAN", git_head="abc123", config_knobs={"ML_ENABLED": True},
    )
    assert m["seed"] == 1
    assert m["pids"] == {"ryu": 10, "backend": 11}
    assert m["t_eval_start_local"] == "2026-08-28 14:00:00"
    assert m["t_eval_start_mono"] == 123.456
    assert m["verdict"] == "CLEAN"
    assert m["git_head"] == "abc123"
    assert m["config_knobs"]["ML_ENABLED"] is True
