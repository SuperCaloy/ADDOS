"""T17: Detection Time reporting surface (plan measurement-2026-08-27 R1).

Owner decision 2026-08-27: the report shows ONLY the plain Detection Time
(mean); the earlier median/P95 experiment was rolled back. These tests pin:
- get_latency_metrics still computes the AVG correctly over the documented
  population (rows where BOTH latencies are non-null within the window).
- report.py section 2c carries exactly one Detection Time row, no Median /
  P95 variants, with a plain-language description.
"""
import sqlite3

import pytest

from backend.database.writer import get_latency_metrics


@pytest.fixture()
def seed_detected(temp_db):
    """Insert detected mitigation_events rows directly.

    Rows are (src_ip, ts, detection_ms, mitigation_ms); NULL passes through.
    """
    def _seed(rows):
        conn = sqlite3.connect(temp_db)
        try:
            conn.executemany(
                """
                INSERT INTO mitigation_events
                    (timestamp, src_ip, predicted_class, attack_vector,
                     confidence, priority, action_taken, event_type,
                     detection_ms, mitigation_ms)
                VALUES (?, ?, 'DDoS', 'SYN Flood', 0.9, 'High',
                        'Blocked', 'detected', ?, ?)
                """,
                [(ts, ip, dms, mms) for (ip, ts, dms, mms) in rows],
            )
            conn.commit()
        finally:
            conn.close()

    return _seed


def test_avg_over_window_and_null_exclusions(seed_detected):
    seed_detected([
        # in-window valid pair
        ("10.0.0.10", "2026-08-27 12:00:01", 100.0, 5.0),
        ("10.0.0.11", "2026-08-27 12:00:02", 300.0, 6.0),
        # NULL detection_ms: outside the population
        ("10.0.0.12", "2026-08-27 12:00:03", None, 6.0),
        # huge but outside the queried day: must not skew results
        ("10.0.0.13", "2026-08-26 23:59:59", 99999.0, 9.0),
        ("10.0.0.14", "2026-08-28 00:00:00", 99999.0, 9.0),
    ])

    m = get_latency_metrics("2026-08-27", "2026-08-27")

    assert m["detection_ms"] == pytest.approx(200.0)
    assert m["mitigation_ms"] == pytest.approx(5.5)


def test_empty_window_returns_zero_not_crash(temp_db):
    m = get_latency_metrics("2030-01-01", "2030-01-01")

    assert m["detection_ms"] == 0
    assert m["mitigation_ms"] == 0


def test_report_shows_only_plain_detection_time_row():
    """Owner decision: single mean row, no percentile variants, simple text."""
    src = open(
        "/home/killua/Documents/ADDOS-NEW/backend/api/report.py"
    ).read()
    assert '"Detection Time"' in src
    assert "Detection Time (Median)" not in src
    assert "Detection Time (P95)" not in src
    assert src.count('"Detection Time"') == 1


def test_report_ends_with_admin_signature_block():
    """Last section: professional sign-off block for the network administrator."""
    src = open(
        "/home/killua/Documents/ADDOS-NEW/backend/api/report.py"
    ).read()
    # Unnumbered heading (owner request: no leading section number)
    assert "Verification and Approval" in src
    assert '"6.  Verification' not in src
    # Single signatory at left (rule, caption, bold role), date at right;
    # two separate rules with a gap between the columns, no underline.
    assert '"SIGNATURE OVER PRINTED NAME"' in src
    assert '"DATE"' in src
    assert "<b>Network Administrator</b>" in src
    assert "<u>" not in src
    # Captions and role are centered under their rules (owner request)
    _sig_src = src[src.index("sig_role = Paragraph"):
                   src.index("story.append(sig_tbl)")]
    assert '"CENTER"' in _sig_src
    assert '"LEFT"' not in _sig_src
    # The role Paragraph carries its own style: must be centered too
    assert "alignment=1" in _sig_src
    # The block comes after every data section (it is the report's tail)
    assert src.index("Verification and Approval") \
        > src.index("IP Attack History")
