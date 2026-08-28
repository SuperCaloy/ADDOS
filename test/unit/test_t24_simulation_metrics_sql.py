"""T24: window-exact metric extraction from logs/ddos.db.

The backend writer helpers rebuild bounds as {date} 00:00:00/23:59:59 and
discard the time component. The runner MUST NOT use them; these tests pin
simulation.metrics_sql to exact naive-local timestamp bounds.
"""
from datetime import datetime

import pytest

from simulation.metrics_sql import (
    MetricsSanityError,
    extract_window,
    mitigation_events_date_rows,
    require_rows,
)

T0 = datetime(2026, 8, 28, 10, 0, 0)
T1 = datetime(2026, 8, 28, 10, 10, 0)


def _seed_summary(db, ts, **cols):
    base = dict(
        timestamp=ts,
        total_flows_observed=10, threats_mitigated=0, true_negatives_passed=0,
        false_positives=0, tp=0, tn=0, fn=0,
        if_tp=0, if_fp=0, if_tn=0, if_fn=0,
        rf_tp=0, rf_fp=0, rf_tn=0, rf_fn=0,
        rf_tp_syn=0, rf_fp_syn=0, rf_tn_syn=0, rf_fn_syn=0,
        rf_tp_icmp=0, rf_fp_icmp=0, rf_tn_icmp=0, rf_fn_icmp=0,
        rf_tp_udp=0, rf_fp_udp=0, rf_tn_udp=0, rf_fn_udp=0,
    )
    base.update(cols)
    keys = ",".join(base)
    marks = ",".join("?" for _ in base)
    db.execute(f"INSERT INTO traffic_summary ({keys}) VALUES ({marks})",
               tuple(base.values()))


def _seed_event(db, ts, detection_ms=None, mitigation_ms=None, vector="SYN Flood"):
    db.execute(
        "INSERT INTO mitigation_events (timestamp, src_ip, predicted_class,"
        " attack_vector, confidence, priority, action_taken, detection_ms,"
        " mitigation_ms) VALUES (?, '10.0.0.10', ?, ?, 0.9, 'High', 'ban', ?, ?)",
        (ts, vector, vector, detection_ms, mitigation_ms))


def _seed_sysmetric(db, ts, cpu, is_attack, ctrl_cpu=12.0):
    db.execute(
        "INSERT INTO system_metrics (timestamp, cpu_percent, mem_mb,"
        " pps_processed, is_attack, ctrl_cpu_percent, ctrl_mem_mb,"
        " is_mitigating, proc_cpu_percent)"
        " VALUES (?, ?, 100.0, 5.0, ?, ?, 50.0, 0, 3.0)",
        (ts, cpu, is_attack, ctrl_cpu))


@pytest.fixture()
def seeded_db(temp_db):
    import backend.database.db as db
    # inside the window
    _seed_summary(db, "2026-08-28 10:01:00", if_tp=8, if_fp=2, if_tn=80, if_fn=2,
                  rf_tp_syn=4, rf_fn_syn=1, rf_tn_syn=50, rf_fp_syn=1,
                  rf_tp_icmp=2, rf_fn_icmp=1, rf_tn_icmp=40, rf_fp_icmp=0,
                  rf_tp_udp=1, rf_fn_udp=0, rf_tn_udp=30, rf_fp_udp=1)
    _seed_summary(db, "2026-08-28 10:09:59", if_tp=2, if_fp=1, if_tn=20, if_fn=0)
    # outside the window (before and after) must never be counted
    _seed_summary(db, "2026-08-28 09:59:59", if_tp=100, if_fp=100, if_tn=0, if_fn=0)
    _seed_summary(db, "2026-08-28 10:10:01", if_tp=100, if_fp=100, if_tn=0, if_fn=0)
    _seed_event(db, "2026-08-28 10:02:00", detection_ms=100.0, mitigation_ms=200.0)
    _seed_event(db, "2026-08-28 10:03:00", detection_ms=300.0, mitigation_ms=None)
    _seed_event(db, "2026-08-28 11:00:00", detection_ms=9999.0, mitigation_ms=9999.0)
    _seed_sysmetric(db, "2026-08-28 10:02:00", cpu=30.0, is_attack=1, ctrl_cpu=20.0)
    _seed_sysmetric(db, "2026-08-28 10:05:00", cpu=10.0, is_attack=0, ctrl_cpu=5.0)
    return db


def test_extract_window_counts_only_exact_bounds(seeded_db):
    m = extract_window(T0, T1)
    assert m["if"]["tp"] == 10
    assert m["if"]["fp"] == 3
    assert m["if"]["tn"] == 100
    assert m["if"]["fn"] == 2


def test_extract_window_derived_ratios(seeded_db):
    m = extract_window(T0, T1)
    tp, fp, tn, fn = 10, 3, 100, 2
    assert m["if"]["precision"] == pytest.approx(tp / (tp + fp))
    assert m["if"]["recall"] == pytest.approx(tp / (tp + fn))
    assert m["if"]["accuracy"] == pytest.approx((tp + tn) / (tp + fp + tn + fn))
    assert m["if"]["fpr"] == pytest.approx(fp / (fp + tn))


def test_extract_window_handles_empty_derived_values(temp_db):
    import backend.database.db as db
    m = extract_window(T0, T1)
    assert m["if"]["tp"] == 0
    assert m["if"]["precision"] is None


def test_extract_window_rf_per_vector(seeded_db):
    m = extract_window(T0, T1)
    assert m["rf"]["syn"]["tp"] == 4
    assert m["rf"]["syn"]["fn"] == 1
    assert m["rf"]["icmp"]["tp"] == 2
    assert m["rf"]["udp"]["fp"] == 1
    assert m["rf"]["syn"]["fnr"] == pytest.approx(1 / 5)


def test_extract_window_latency_ignores_null_and_out_of_window(seeded_db):
    m = extract_window(T0, T1)
    assert m["latency"]["detection_ms_avg"] == pytest.approx(200.0)
    assert m["latency"]["detection_ms_n"] == 2
    assert m["latency"]["mitigation_ms_avg"] == pytest.approx(200.0)
    assert m["latency"]["mitigation_ms_n"] == 1


def test_extract_window_cpu_attack_vs_baseline(seeded_db):
    m = extract_window(T0, T1)
    assert m["cpu"]["attack"]["cpu_avg"] == pytest.approx(30.0)
    assert m["cpu"]["attack"]["ctrl_cpu_avg"] == pytest.approx(20.0)
    assert m["cpu"]["baseline"]["cpu_avg"] == pytest.approx(10.0)


def test_require_rows_passes_and_fails(seeded_db):
    require_rows(T0, T1)  # rows exist -> ok
    with pytest.raises(MetricsSanityError):
        require_rows(datetime(2026, 8, 28, 12, 0, 0), datetime(2026, 8, 28, 12, 5, 0))


def test_mitigation_events_date_rows_for_report_404_check(seeded_db):
    assert mitigation_events_date_rows("2026-08-28", "2026-08-28") >= 1
    assert mitigation_events_date_rows("2026-01-01", "2026-01-01") == 0


def test_build_wave_metrics_anchors_to_gt_registration(seeded_db):
    from datetime import timedelta
    from simulation.run_benchmark import build_wave_metrics
    # wave planned window 10:00-10:10; GT registered at 10:05
    waves = [{"name": "syn_wave", "ips": ["10.0.0.10"]}]
    bounds = [{"name": "syn_wave", "start": T0, "end": T1}]
    seen_gt = {"10.0.0.10": T0 + timedelta(seconds=300)}
    m = build_wave_metrics(waves, bounds, seen_gt)
    assert m["syn_wave"]["window"]["start"] == "2026-08-28 10:05:00"
    assert m["syn_wave"]["window"]["end"] == "2026-08-28 10:10:00"
    # the 10:01 row (if_tp=8) is before GT registration: excluded from the wave
    assert m["syn_wave"]["if"]["tp"] == 2


def test_build_wave_metrics_falls_back_to_planned_window(seeded_db):
    from simulation.run_benchmark import build_wave_metrics
    waves = [{"name": "udp_wave", "ips": []}]
    bounds = [{"name": "udp_wave", "start": T0, "end": T1}]
    m = build_wave_metrics(waves, bounds, {})
    assert m["udp_wave"]["window"]["start"] == "2026-08-28 10:00:00"


def test_build_wave_metrics_skips_unknown_phase(seeded_db):
    from simulation.run_benchmark import build_wave_metrics
    m = build_wave_metrics([{"name": "ghost_wave", "ips": ["10.0.0.6"]}],
                           [{"name": "syn_wave", "start": T0, "end": T1}],
                           {"10.0.0.6": T0})
    assert m == {}
