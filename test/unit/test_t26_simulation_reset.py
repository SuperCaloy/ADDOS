"""T26: reset_behavioral_state manual repair tool.

Demoted per R5a (fresh-DB-per-session): the runner never auto-invokes it.
Pins: roster scope (15 attackers + 5 legit + 5 retired), PROJECT_ROOT-anchored
default DB, refusal while a backend is live (R5c), non-interactive abort.
"""
import sqlite3
from pathlib import Path

import pytest

import simulation.reset_behavioral_state as rs


def _insert(conn, table, ip):
    if table == "ip_attack_history":
        conn.execute(
            "INSERT INTO ip_attack_history (src_ip, attack_vector, if_score,"
            " confidence, priority, phase_reached, first_seen, unblocked_at,"
            " duration_sec, unblock_reason, ban_level, offence_count)"
            " VALUES (?, 'SYN Flood', 0.9, 0.9, 'High', 2, '2026-08-28 10:00:00',"
            " '2026-08-28 10:01:00', 60, 'Test', 1, 1)", (ip,))
    else:
        conn.execute(
            "INSERT INTO quarantine_state (src_ip, phase, attack_vector,"
            " if_score, confidence, action_taken, permanent, updated_at)"
            " VALUES (?, 2, 'SYN Flood', 0.9, 0.9, 'drop', 0,"
            " '2026-08-28 10:00:00')", (ip,))


@pytest.fixture()
def dirty_db(tmp_path):
    p = tmp_path / "ddos.db"
    conn = sqlite3.connect(p)
    conn.executescript(rs.SCHEMA_MIN)
    for i in (6, 10, 23):            # attackers
        _insert(conn, "ip_attack_history", f"10.0.0.{i}")
    for i in (1, 5):                 # legit (R3c: flash-crowd FPs)
        _insert(conn, "ip_attack_history", f"10.0.0.{i}")
    for i in (19, 26):               # retired
        _insert(conn, "ip_attack_history", f"10.0.0.{i}")
    _insert(conn, "ip_attack_history", "10.0.0.99")   # out of scope: must stay
    _insert(conn, "quarantine_state", "10.0.0.6")
    conn.commit()
    conn.close()
    return p


def test_db_default_anchored_to_project_root():
    assert rs.DB_DEFAULT == Path(__file__).resolve().parents[2] / "logs" / "ddos.db"


def test_roster_scope_matches_plan():
    assert rs.ATTACKER_IPS == [f"10.0.0.{i}" for i in
                               (6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 22, 23)]
    assert set(rs.RETIRE_IPS) == {f"10.0.0.{i}" for i in (19, 24, 25, 26, 27)}
    assert set(rs.LEGIT_IPS) == {f"10.0.0.{i}" for i in (1, 2, 3, 4, 5)}


def test_reset_clears_scope_and_keeps_out_of_scope(dirty_db):
    ok, msg = rs.reset(dirty_db, assume_yes=True, backend_probe=lambda: False)
    assert ok
    conn = sqlite3.connect(dirty_db)
    n_scope = conn.execute(
        "SELECT COUNT(*) FROM ip_attack_history WHERE src_ip IN (%s)"
        % ",".join("?" * len(rs.SCOPE_IPS)), rs.SCOPE_IPS).fetchone()[0]
    n_left = conn.execute("SELECT COUNT(*) FROM ip_attack_history").fetchone()[0]
    n_quar = conn.execute("SELECT COUNT(*) FROM quarantine_state").fetchone()[0]
    conn.close()
    assert n_scope == 0
    assert n_left == 1        # 10.0.0.99 untouched
    assert n_quar == 0


def test_reset_refuses_live_backend(dirty_db):
    ok, msg = rs.reset(dirty_db, assume_yes=True, backend_probe=lambda: True)
    assert not ok
    conn = sqlite3.connect(dirty_db)
    n = conn.execute("SELECT COUNT(*) FROM ip_attack_history").fetchone()[0]
    conn.close()
    assert n == 8             # nothing deleted (7 scoped + 1 out-of-scope)


def test_reset_absent_db_is_ok(tmp_path):
    ok, msg = rs.reset(tmp_path / "nope.db", assume_yes=True,
                       backend_probe=lambda: False)
    assert ok


def test_reset_interactive_decline_aborts(dirty_db):
    ok, msg = rs.reset(dirty_db, assume_yes=False, backend_probe=lambda: False,
                       input_fn=lambda prompt: "n")
    assert not ok
    conn = sqlite3.connect(dirty_db)
    n = conn.execute("SELECT COUNT(*) FROM ip_attack_history").fetchone()[0]
    conn.close()
    assert n == 8


def test_reset_eof_on_non_interactive_prompt_aborts(dirty_db):
    def _eof(prompt):
        raise EOFError

    ok, msg = rs.reset(dirty_db, assume_yes=False, backend_probe=lambda: False,
                       input_fn=_eof)
    assert not ok


def test_reset_accepts_interactive_yes(dirty_db):
    ok, msg = rs.reset(dirty_db, assume_yes=False, backend_probe=lambda: False,
                       input_fn=lambda prompt: "y")
    assert ok
    conn = sqlite3.connect(dirty_db)
    n = conn.execute("SELECT COUNT(*) FROM ip_attack_history").fetchone()[0]
    conn.close()
    assert n == 1
