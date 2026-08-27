"""T7: detection_features flusher semantics (A3).

Rows must buffer in arrival order, carry their ENQUEUE-time timestamp,
flush FIFO, drop-oldest with a visible counter on overflow, and survive a
batch-level failure via per-row fallback.
"""
import datetime
import types

import pytest

from backend.database import writer


@pytest.fixture()
def frozen_clock(monkeypatch):
    fixed = datetime.datetime(2026, 8, 25, 12, 0, 0)

    class _FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(writer, "datetime", types.SimpleNamespace(datetime=_FrozenDateTime))
    return fixed


def _feature_rows_in_db(temp_db):
    import sqlite3
    conn = sqlite3.connect(temp_db)
    try:
        return conn.execute(
            "SELECT id, timestamp, src_ip FROM detection_features ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def _emit(ip, if_score=0.5):
    writer.log_detection_features(
        src_ip=ip, if_score=if_score, is_anomaly=False,
        attack_class="Normal", confidence=0.1,
        flow_stats={"packet_count": 10}, switch_stats={},
    )


def test_rows_buffer_then_flush_fifo_with_enqueue_timestamps(
        temp_db, frozen_clock, monkeypatch):
    monkeypatch.setattr(writer, "_FEATURES_BUF_CAP", 100)
    writer._features_buf.clear()

    stamps = []
    base = datetime.datetime(2026, 8, 25, 12, 0, 0)

    class _FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return base

    class _SteppedDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return stamps[-1]

    for i, ip in enumerate(("10.0.0.61", "10.0.0.62", "10.0.0.63")):
        step = base + datetime.timedelta(seconds=i + 1)
        stamps.append(step)
        monkeypatch.setattr(writer, "datetime",
                            types.SimpleNamespace(datetime=_SteppedDateTime))
        _emit(ip)

    monkeypatch.setattr(writer, "datetime",
                        types.SimpleNamespace(datetime=_FrozenDateTime))

    writer.flush_detection_features()
    rows = _feature_rows_in_db(temp_db)
    assert [r[2] for r in rows] == ["10.0.0.61", "10.0.0.62", "10.0.0.63"]
    assert rows[0][1] == "2026-08-25 12:00:01"
    assert rows[2][1] == "2026-08-25 12:00:03"
    writer._features_buf.clear()


def test_overflow_drops_oldest_with_counter(temp_db, frozen_clock, monkeypatch):
    monkeypatch.setattr(writer, "_FEATURES_BUF_CAP", 5)
    writer._features_buf.clear()
    before = writer.features_overflow_count()

    for i in range(7):
        _emit(f"10.0.0.7{i}")
    assert writer.features_overflow_count() == before + 2
    writer.flush_detection_features()
    rows = _feature_rows_in_db(temp_db)
    assert len(rows) == 5
    assert rows[0][2] == "10.0.0.72"
    assert rows[-1][2] == "10.0.0.76"
    writer._features_buf.clear()


def test_flush_failure_falls_back_to_per_row(temp_db, frozen_clock, monkeypatch):
    monkeypatch.setattr(writer, "_FEATURES_BUF_CAP", 100)
    writer._features_buf.clear()
    real_executemany = writer.executemany

    def _boom(sql, params_list):
        raise RuntimeError("injected executemany failure")

    monkeypatch.setattr(writer, "executemany", _boom)
    _emit("10.0.0.81")
    _emit("10.0.0.82")
    writer.flush_detection_features()
    rows = _feature_rows_in_db(temp_db)
    assert [r[2] for r in rows] == ["10.0.0.81", "10.0.0.82"]
    writer._features_buf.clear()


def test_ml_off_still_skips_buffering(temp_db, frozen_clock, monkeypatch):
    from backend.config import ML_ENABLED as _unused
    import backend.database.writer as w
    monkeypatch.setattr(w, "ML_ENABLED", False)
    w._features_buf.clear()
    _emit("10.0.0.83")
    assert w._features_buf == []
