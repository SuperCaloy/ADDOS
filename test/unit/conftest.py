import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import sqlite3

import pytest


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Redirect the backend database to a fresh per-test file.

    Must run before any backend.database.db.get_connection() call so the
    schema is created inside tmp_path instead of logs/ddos.db.
    """
    import backend.database.db as db

    db_path = str(tmp_path / "test_ddos.db")
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db._conn = None
    db.get_connection()

    import backend.database.writer as w
    rep_cache = getattr(w, "_reputation_cache", None)
    if rep_cache is not None:
        rep_cache.clear()

    yield db_path
    if db._conn is not None:
        try:
            db._conn.close()
        except Exception:
            pass
        db._conn = None


@pytest.fixture()
def seed_history(temp_db):
    """Insert ip_attack_history rows directly, bypassing production writers.

    Rows are (src_ip, unblocked_at) tuples; other columns get inert values.
    Direct SQL keeps seeding independent of any caching layer under test.
    """
    def _seed(rows):
        conn = sqlite3.connect(temp_db)
        try:
            conn.executemany(
                """
                INSERT INTO ip_attack_history
                    (src_ip, attack_vector, if_score, confidence, priority,
                     phase_reached, first_seen, unblocked_at, duration_sec,
                     unblock_reason, ban_level, offence_count, reputation_score)
                VALUES (?, 'SYN Flood', 0.9, 0.9, 'High', 2,
                        '2026-08-25 10:00:00', ?, 60, 'Test', 1, 1, 2.0)
                """,
                [(ip, ts) for (ip, ts) in rows],
            )
            conn.commit()
        finally:
            conn.close()

    return _seed


@pytest.fixture(scope="session")
def real_models():
    """Load the real model pickles once for tests that need live inference."""
    from backend.models import loader

    loader.load_all()
    return loader
