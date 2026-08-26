"""T2: reputation decay equivalence (get_offense_count / get_decay_score).

The production formula is: for each ip_attack_history row in insertion
order, skip unparseable timestamps, accumulate 2.0 * 0.5**(hours/24) with a
per-call now(), then return min(round(score, 4), 10.0). These tests pin the
formula, the round-before-clamp order, threshold crossings used by
should_blackhole routing, and cache-consistency under write failure once
A1 lands. They must pass before AND after A1.
"""
import datetime
import sqlite3
import types

import pytest

from backend.database import writer
from backend.mitigation import behavioral


@pytest.fixture()
def frozen_now(monkeypatch):
    """Freeze writer's clock so expected values are bit-reproducible."""
    fixed = datetime.datetime(2026, 8, 25, 12, 0, 0)

    class _FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(writer, "datetime", types.SimpleNamespace(datetime=_FrozenDateTime))
    return fixed


def _expected_score(temp_db, src_ip, now):
    """Independent recomputation: raw sqlite read, rowid order, same ops."""
    conn = sqlite3.connect(temp_db)
    try:
        rows = conn.execute(
            "SELECT unblocked_at FROM ip_attack_history WHERE src_ip = ? ORDER BY rowid",
            (src_ip,),
        ).fetchall()
    finally:
        conn.close()
    score = 0.0
    for (ts,) in rows:
        try:
            dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            hours = (now - dt).total_seconds() / 3600.0
            score += 2.0 * (0.5 ** (hours / 24.0))
        except Exception:
            continue
    return min(round(score, 4), 10.0)


def test_decay_matches_independent_recomputation(temp_db, seed_history, frozen_now):
    seed_history([
        ("10.0.0.7", "2026-08-25 11:00:00"),
        ("10.0.0.7", "2026-08-25 11:30:00"),
        ("10.0.0.8", "2026-08-24 12:00:00"),
    ])
    assert writer.get_offense_count("10.0.0.7") == pytest.approx(
        _expected_score(temp_db, "10.0.0.7", frozen_now), abs=1e-9)
    # 24h-old offense contributes exactly half of a fresh one.
    assert writer.get_offense_count("10.0.0.8") == pytest.approx(1.0, abs=1e-9)


def test_unparseable_and_empty_history_follow_formula(temp_db, seed_history, frozen_now):
    seed_history([("10.0.0.9", "not-a-timestamp")])
    assert writer.get_offense_count("10.0.0.9") == 0.0
    assert writer.get_offense_count("10.0.0.99") == 0.0


def test_same_second_duplicates_each_contribute(temp_db, seed_history, frozen_now):
    stamp = "2026-08-25 11:59:59"
    seed_history([("10.0.0.10", stamp), ("10.0.0.10", stamp)])
    one_second_hours = (1.0 / 3600.0) / 24.0
    fresh = 2.0 * (0.5 ** one_second_hours)
    assert writer.get_offense_count("10.0.0.10") == pytest.approx(
        min(round(fresh * 2, 4), 10.0), abs=1e-9)


def test_blackhole_threshold_crossing_exact_at_10(temp_db, seed_history, frozen_now):
    # Six near-simultaneous offenses overshoot the cap: raw sum ~12, the
    # function rounds THEN clamps, so the returned value must be exactly 10.0.
    base = datetime.datetime(2026, 8, 25, 11, 59, 0)
    stamps = [(base + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
              for i in range(6)]
    seed_history([("10.0.0.11", s) for s in stamps])
    score = behavioral.get_decay_score("10.0.0.11")
    assert score == 10.0
    assert behavioral.should_blackhole("10.0.0.11", 0) is True


def test_below_threshold_does_not_blackhole(temp_db, seed_history, frozen_now):
    stamps = ["2026-08-25 11:59:00"] * 3
    seed_history([("10.0.0.12", s) for s in stamps])
    assert behavioral.get_decay_score("10.0.0.12") < 10.0
    assert behavioral.should_blackhole("10.0.0.12", 0) is False


def test_fresh_offense_immediately_visible_to_decay(temp_db, seed_history, frozen_now):
    # Seed five near-simultaneous offenses (raw sum just under 10), then one
    # more must cross the clamp instantly, never one read later. This is what
    # a naive TTL cache would break.
    stamps = ["2026-08-25 11:59:59"] * 5
    seed_history([("10.0.0.13", s) for s in stamps])
    before = behavioral.get_decay_score("10.0.0.13")
    assert before < 10.0
    behavioral.record_offense(
        src_ip="10.0.0.13", attack_vector="SYN Flood", if_score=0.9,
        confidence=0.9, priority="High", phase_reached=2,
        first_seen="2026-08-25 11:58:00", unblock_reason="Ban Expired",
        ban_level=1, offence_count=1,
    )
    after = behavioral.get_decay_score("10.0.0.13")
    assert after == 10.0
    assert behavioral.should_blackhole("10.0.0.13", 0) is True


def test_insert_failure_leaves_decay_unchanged(temp_db, seed_history, frozen_now, monkeypatch):
    seed_history([("10.0.0.14", "2026-08-25 11:59:00")])
    baseline = behavioral.get_decay_score("10.0.0.14")

    real_execute = writer.execute

    def _boom(sql, params=()):
        if "INSERT INTO ip_attack_history" in sql:
            raise RuntimeError("injected insert failure")
        return real_execute(sql, params)

    monkeypatch.setattr(writer, "execute", _boom)
    behavioral.record_offense(
        src_ip="10.0.0.14", attack_vector="SYN Flood", if_score=0.9,
        confidence=0.9, priority="High", phase_reached=2,
        first_seen="2026-08-25 11:58:00", unblock_reason="Ban Expired",
        ban_level=1, offence_count=1,
    )
    assert behavioral.get_decay_score("10.0.0.14") == baseline

    monkeypatch.undo()
    behavioral.record_offense(
        src_ip="10.0.0.14", attack_vector="SYN Flood", if_score=0.9,
        confidence=0.9, priority="High", phase_reached=2,
        first_seen="2026-08-25 11:58:00", unblock_reason="Ban Expired",
        ban_level=1, offence_count=1,
    )
    assert behavioral.get_decay_score("10.0.0.14") > baseline


def test_uncached_counts_stay_live_reads(temp_db, seed_history, frozen_now):
    # get_offence_total_count / get_ban_level use different queries; they must
    # keep reflecting writes immediately regardless of any decay caching.
    seed_history([("10.0.0.15", "2026-08-25 11:00:00")])
    assert writer.get_offense_total_count("10.0.0.15") == 1
    assert writer.get_ban_level("10.0.0.15") == 1


def test_offense_committed_during_cache_load_is_included(
        temp_db, seed_history, frozen_now, monkeypatch):
    # Regression guard for the A1 miss-path race: an offense committed while
    # the first load is running must be included, because the seq re-check
    # detects the write and forces one reload after the SELECT.
    seed_history([("10.0.0.16", "2026-08-25 11:59:00")])

    import backend.database.db as db_mod
    real_query = db_mod.query
    fired = {"once": False}

    def _query_with_competing_insert(sql, params=()):
        if not fired["once"] and "FROM ip_attack_history" in sql:
            fired["once"] = True
            writer.log_attack_history(
                src_ip="10.0.0.16", attack_vector="SYN Flood",
                if_score=0.9, confidence=0.9, priority="High",
                phase_reached=2, first_seen="2026-08-25 11:58:00",
                unblock_reason="Ban Expired", ban_level=1, offence_count=1,
            )
        return real_query(sql, params)

    monkeypatch.setattr(db_mod, "query", _query_with_competing_insert)
    score = writer.get_offense_count("10.0.0.16")
    expected = _expected_score(temp_db, "10.0.0.16", frozen_now)
    assert score == pytest.approx(expected, abs=1e-9)


def test_concurrent_offense_writes_never_omitted_nor_duplicated(
        temp_db, frozen_now):
    # Threaded stress on the atomic-commit contract: writers record offenses
    # through the production funnel while readers hammer the cached read.
    # Final cached score must equal the independent DB recomputation exactly
    # (no omitted row from a lost append, no duplicated row from a
    # load/append race).
    import threading

    ip = "10.0.0.17"
    n_offenses = 5

    def _writer():
        behavioral.record_offense(
            src_ip=ip, attack_vector="SYN Flood", if_score=0.9,
            confidence=0.9, priority="High", phase_reached=2,
            first_seen="2026-08-25 11:58:00", unblock_reason="Ban Expired",
            ban_level=1, offence_count=1,
        )

    stop = {"flag": False}
    read_scores = []

    def _reader():
        while not stop["flag"]:
            read_scores.append(behavioral.get_decay_score(ip))

    readers = [threading.Thread(target=_reader) for _ in range(3)]
    for t in readers:
        t.start()
    threads = [threading.Thread(target=_writer) for _ in range(n_offenses)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop["flag"] = True
    for t in readers:
        t.join()

    final = writer.get_offense_count(ip)
    expected = _expected_score(temp_db, ip, frozen_now)
    assert final == pytest.approx(expected, abs=1e-9)

    conn = sqlite3.connect(temp_db)
    try:
        rows = conn.execute(
            "SELECT COUNT(*) FROM ip_attack_history WHERE src_ip = ?", (ip,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert rows == n_offenses

    # Structural exactly-once proof, immune to the 10.0 clamp masking score
    # inflation: the cached timestamp list must hold exactly one entry per
    # committed offense. A lost append makes it short; a load/append race
    # duplicate makes it long.
    cached_stamps = writer._reputation_cache.get(ip)
    assert cached_stamps is not None
    assert len(cached_stamps) == n_offenses

    # Every intermediate read must also match a clamp-consistent prefix:
    # scores are monotonically non-decreasing here.
    assert all(a <= b + 1e-9 for a, b in zip(read_scores, read_scores[1:]))
