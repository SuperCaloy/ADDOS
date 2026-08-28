"""get_offense_total_count must survive a benchmark reset.

The dashboard Offences pill reads this value. After reset the episode rows
are gone, so the persisted offence_totals ledger total must be added on top
of any live ip_attack_history count.
"""
import sqlite3

from backend.database import writer


def _make_ledger(db_path, rows):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS offence_totals ("
            "src_ip TEXT PRIMARY KEY, total_offences INTEGER DEFAULT 0, "
            "last_ban_level INTEGER DEFAULT 0, updated_at TEXT)"
        )
        conn.executemany(
            "INSERT INTO offence_totals(src_ip, total_offences) VALUES(?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def test_live_rows_counted_without_ledger(temp_db, seed_history):
    seed_history([
        ("10.8.8.1", "2026-08-25 10:00:00"),
        ("10.8.8.1", "2026-08-25 11:00:00"),
    ])

    assert writer.get_offense_total_count("10.8.8.1") == 2


def test_ledger_total_added_to_live_rows(temp_db, seed_history):
    seed_history([("10.8.8.2", "2026-08-25 10:00:00")])
    _make_ledger(temp_db, [("10.8.8.2", 7)])

    assert writer.get_offense_total_count("10.8.8.2") == 8


def test_ledger_only_ip_survives_history_delete(temp_db, seed_history):
    seed_history([("10.8.8.3", "2026-08-25 10:00:00")])
    _make_ledger(temp_db, [("10.8.8.3", 5)])

    conn = sqlite3.connect(temp_db)
    try:
        conn.execute("DELETE FROM ip_attack_history WHERE src_ip = '10.8.8.3'")
        conn.commit()
    finally:
        conn.close()

    assert writer.get_offense_total_count("10.8.8.3") == 5


def test_missing_ledger_table_returns_live_count(temp_db, seed_history):
    seed_history([("10.8.8.4", "2026-08-25 10:00:00")])

    assert writer.get_offense_total_count("10.8.8.4") == 1


def test_unknown_ip_with_ledger_data_is_zero(temp_db):
    _make_ledger(temp_db, [("10.8.8.5", 3)])

    assert writer.get_offense_total_count("10.9.9.9") == 0
