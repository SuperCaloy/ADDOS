"""T27: cross-session aggregation with adaptive spread stopping rule.

spread (max-min) must be <= claimed-margin/3 on BOTH detection-latency
median and accuracy for a READY verdict (amendment item 4, TriScale-style).
"""
import json

import pytest

from simulation.aggregate import aggregate_runs, outlier_runs, spread_stats


def _run(acc, lat):
    return {"if": {"accuracy": acc}, "latency": {"detection_ms_avg": lat}}


def test_spread_stats_median_range_mean_sd():
    s = spread_stats([1.0, 2.0, 3.0, 4.0])
    assert s["n"] == 4
    assert s["median"] == 2.5
    assert s["range"] == 3.0
    assert s["mean"] == pytest.approx(2.5)
    assert s["sd"] > 0


def test_spread_stats_skips_none():
    s = spread_stats([1.0, None, 3.0])
    assert s["n"] == 2


def test_aggregate_ready_when_both_spreads_within_third_of_margin():
    runs = [_run(0.97, 900.0), _run(0.98, 950.0), _run(0.98, 1000.0)]
    res = aggregate_runs(runs, latency_margin_ms=600.0, accuracy_margin=0.06)
    assert res["verdict"] == "READY"


def test_aggregate_needs_more_sessions_on_latency_spread():
    runs = [_run(0.97, 100.0), _run(0.98, 100.0), _run(0.98, 900.0)]
    res = aggregate_runs(runs, latency_margin_ms=600.0, accuracy_margin=0.06)
    assert res["verdict"] == "NEED-MORE-SESSIONS"
    assert res["latency"]["range"] == 800.0
    assert res["latency"]["ratio"] > 3


def test_aggregate_needs_more_sessions_on_accuracy_spread():
    runs = [_run(0.80, 100.0), _run(0.98, 100.0), _run(0.99, 100.0)]
    res = aggregate_runs(runs, latency_margin_ms=600.0, accuracy_margin=0.06)
    assert res["verdict"] == "NEED-MORE-SESSIONS"


def test_outlier_flags_more_than_two_sd():
    runs = [_run(0.97, 100.0)] * 7 + [_run(0.40, 100.0)]
    flags = outlier_runs(runs)
    assert flags == [7]


def test_aggregate_reads_metrics_json_files(tmp_path, capsys):
    for i, (a, l) in enumerate([(0.97, 900.0), (0.98, 950.0), (0.98, 1000.0)]):
        (tmp_path / f"m{i}.json").write_text(json.dumps(_run(a, l)))
    from simulation.aggregate import main
    argv = [str(p) for p in sorted(tmp_path.glob("*.json"))] + [
        "--latency-margin-ms", "600", "--accuracy-margin", "0.06"]
    rc = main(argv)
    assert rc == 0
    out = capsys.readouterr().out
    assert "READY" in out
