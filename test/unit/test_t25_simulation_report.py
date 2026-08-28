"""T25: auto-generated benchmark report (simulation.report_gen).

Pins: verdict gating, naive-local date args, unique timestamped filename,
PROJECT_ROOT-anchored output dir, 15 s HTTP timeout, 404 SQL cross-check
(fail loud if rows exist), skip-and-warn on transport failure.
"""
from datetime import datetime, timedelta

import pytest

import simulation.report_gen as rg
from simulation.report_gen import (
    REPORT_TIMEOUT_S,
    report_dates,
    report_filename,
    generate_report,
)

T0 = datetime(2026, 8, 28, 23, 50, 0)
END = T0 + timedelta(minutes=60)  # crosses midnight


def test_report_timeout_is_bounded():
    assert REPORT_TIMEOUT_S == 15.0


def test_report_filename_has_unique_sortable_timestamp():
    assert report_filename(datetime(2026, 8, 28, 14, 30, 5)) == \
        "ddos_report_2026-08-28_14-30-05.pdf"


def test_report_dates_span_midnight_from_session_clock():
    start_date, end_date = report_dates(T0, END)
    assert (start_date, end_date) == ("2026-08-28", "2026-08-29")


def test_report_skipped_for_pilot_and_bad_verdicts(tmp_path):
    calls = []

    def post(url, payload):
        calls.append(url)
        return 200, b"pdf"

    r, why = generate_report(T0, END, tmp_path, verdict="SUSPECT",
                             is_pilot=False, sql_row_check=lambda *a: 5, post=post)
    assert r is None and calls == []
    r, why = generate_report(T0, END, tmp_path, verdict="CLEAN",
                             is_pilot=True, sql_row_check=lambda *a: 5, post=post)
    assert r is None and calls == []


def test_report_written_with_absolute_path(tmp_path):
    def post(url, payload):
        assert payload == {"start_date": "2026-08-28", "end_date": "2026-08-29"}
        return 200, b"%PDF-bytes"

    r, why = generate_report(T0, END, tmp_path / "reports", verdict="CLEAN",
                             is_pilot=False, sql_row_check=lambda *a: 0, post=post)
    assert r is not None and r.is_absolute()
    assert r.read_bytes() == b"%PDF-bytes"
    assert r.name.startswith("ddos_report_")


def test_report_404_with_no_rows_skips(tmp_path):
    def post(url, payload):
        return 404, b""

    r, why = generate_report(T0, END, tmp_path, verdict="CLEAN", is_pilot=False,
                             sql_row_check=lambda s, e: 0, post=post)
    assert r is None


def test_report_404_with_rows_fails_loud(tmp_path):
    def post(url, payload):
        return 404, b""

    with pytest.raises(rg.ReportBug):
        generate_report(T0, END, tmp_path, verdict="CLEAN", is_pilot=False,
                        sql_row_check=lambda s, e: 3, post=post)


def test_report_transport_failure_skips_gracefully(tmp_path):
    def post(url, payload):
        raise TimeoutError("backend died")

    r, why = generate_report(T0, END, tmp_path, verdict="CLEAN", is_pilot=False,
                             sql_row_check=lambda *a: 0, post=post)
    assert r is None
