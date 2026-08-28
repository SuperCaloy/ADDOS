"""T23: benchmark runner timeline, bounds, calibration gate and verdicts.

Covers the pure scheduling/clock logic of simulation.timeline and
simulation.verdicts (sixty-minute-benchmark-runner task).
"""
from datetime import datetime, timedelta

import pytest

from simulation.timeline import (
    EVAL_DURATION_S,
    PHASES,
    anchored_wave_bounds,
    calibration_gate,
    check_clock_drift,
    gt_poll_budget,
    phase_boundaries,
    phase_deadlines,
    phases_for_duration,
    sql_bound,
)
from simulation.verdicts import REPORT_ELIGIBLE, compute_run_verdict

T0 = datetime(2026, 8, 28, 14, 0, 0)


def test_timeline_sums_to_exactly_60_minutes():
    assert sum(p.duration_s for p in PHASES) == EVAL_DURATION_S == 3600


def test_timeline_structure_flash_crowd_early_and_five_waves():
    names = [p.name for p in PHASES]
    assert names[0] == "baseline_soak"
    assert names[1] == "flash_crowd"
    kinds = [(p.name, p.kind) for p in PHASES]
    attacks = [n for n, k in kinds if k == "attack"]
    assert attacks == ["syn_wave", "icmp_wave", "udp_wave", "mixed_a", "mixed_b"]
    vectors = {p.name: p.vector for p in PHASES if p.kind == "attack"}
    assert vectors == {
        "syn_wave": "SYN", "icmp_wave": "ICMP", "udp_wave": "UDP",
        "mixed_a": "MIXED", "mixed_b": "MIXED",
    }
    quiets = [n for n, k in kinds if k == "quiet"]
    assert quiets == ["quiet_1", "quiet_2", "quiet_3", "quiet_4"]


def test_phase_boundaries_are_relative_to_t_eval_start():
    bounds = phase_boundaries(T0)
    assert bounds[0]["name"] == "baseline_soak"
    assert bounds[0]["start"] == T0
    assert bounds[0]["end"] == T0 + timedelta(seconds=240)
    assert bounds[-1]["end"] == T0 + timedelta(seconds=EVAL_DURATION_S)
    # contiguous windows
    for prev, cur in zip(bounds, bounds[1:]):
        assert prev["end"] == cur["start"]


def test_sql_bound_formats_naive_local_with_time_component():
    assert sql_bound(T0) == "2026-08-28 14:00:00"
    assert sql_bound(datetime(2026, 8, 28, 23, 59, 59)) == "2026-08-28 23:59:59"


def test_phases_for_duration_full_run_is_unchanged():
    assert phases_for_duration(3600) == list(PHASES)
    assert phases_for_duration(7200) == list(PHASES)


def test_phases_for_duration_truncates_to_budget():
    phases = phases_for_duration(60)
    assert sum(p.duration_s for p in phases) == 60
    assert phases[0].name == "baseline_soak"
    assert phases[-1].duration_s <= 60


def test_phase_boundaries_respect_custom_phase_list():
    from simulation.timeline import Phase
    custom = [Phase("baseline_soak", 30, "soak"), Phase("syn_wave", 30, "attack", "SYN")]
    bounds = phase_boundaries(T0, phases=custom)
    assert bounds[-1]["end"] == T0 + timedelta(seconds=60)
    assert bounds[-1]["vector"] == "SYN"


def test_wave_bounds_anchored_to_max_actual_gt_start():
    planned_start = T0
    planned_end = T0 + timedelta(seconds=360)
    gt = [T0 + timedelta(seconds=s) for s in (4, 52, 9)]
    start, end = anchored_wave_bounds(planned_start, planned_end, gt_starts=gt)
    assert start == T0 + timedelta(seconds=52)
    assert end == planned_end


def test_wave_bounds_fall_back_to_planned_without_gt():
    start, end = anchored_wave_bounds(T0, T0 + timedelta(seconds=60), gt_starts=[])
    assert (start, end) == (T0, T0 + timedelta(seconds=60))


def test_wave_bounds_honour_actual_end_transition():
    actual_end = T0 + timedelta(seconds=350)
    start, end = anchored_wave_bounds(T0, T0 + timedelta(seconds=360),
                                      gt_starts=[T0], actual_end=actual_end)
    assert end == actual_end


def test_gt_poll_budget_mixed_vs_single_vector():
    assert gt_poll_budget("MIXED") == 90
    for v in ("SYN", "ICMP", "UDP"):
        assert gt_poll_budget(v) == 30


def test_phase_deadlines_are_monotonic_anchored():
    deadlines = phase_deadlines(100.0)
    assert deadlines[0] == 100.0 + 240
    assert deadlines[-1] == 100.0 + 3600
    assert deadlines == sorted(deadlines)


def test_phase_start_deadlines_are_ends_shifted_by_one():
    from simulation.timeline import phase_start_deadlines
    starts = phase_start_deadlines(100.0)
    ends = phase_deadlines(100.0)
    assert starts[0] == 100.0                    # first action fires at T_eval
    assert starts[1] == 100.0 + 240              # second phase starts at first end
    assert starts == [100.0] + ends[:-1]
    assert len(starts) == len(ends)


class _FakeClock:
    def __init__(self, values):
        self.values = list(values)
        self.i = 0

    def __call__(self):
        v = self.values[min(self.i, len(self.values) - 1)]
        self.i += 1
        return v


def test_calibration_gate_passes_after_min_baseline_and_k_clean_polls():
    now = _FakeClock([0, 30, 35, 40])
    polls = iter([(True, True), (True, True), (True, True)])
    result = calibration_gate(lambda: next(polls), baseline_started_mono=0.0,
                              now=now, sleep=lambda s: None)
    assert result["status"] == "passed"
    assert result["polls"] == 3


def test_calibration_gate_requires_min_baseline_elapsed():
    # learned + clean but only 10s of baseline: must not pass yet
    now = _FakeClock([0, 10, 15, 20, 30])
    polls = iter([(True, True)] * 5)
    result = calibration_gate(lambda: next(polls), baseline_started_mono=0.0,
                              now=now, sleep=lambda s: None,
                              min_baseline_s=30.0, cap_s=60.0)
    assert result["status"] == "passed"
    assert result["elapsed_s"] >= 30.0


def test_calibration_gate_degrades_at_cap():
    now = _FakeClock([0, 85, 91])
    polls = iter([(True, True), (False, True), (False, True)])
    result = calibration_gate(lambda: next(polls), baseline_started_mono=0.0,
                              now=now, sleep=lambda s: None)
    assert result["status"] == "degraded"


def test_calibration_gate_clean_streak_resets_on_dirty_poll():
    now = _FakeClock([0, 30, 35, 40, 45, 50, 55])
    polls = iter([(True, True), (True, True), (True, False),
                  (True, True), (True, True), (True, True)])
    result = calibration_gate(lambda: next(polls), baseline_started_mono=0.0,
                              now=now, sleep=lambda s: None)
    assert result["status"] == "passed"
    assert result["polls"] == 6


def test_check_clock_drift_threshold():
    assert check_clock_drift(mono_delta=60.0, wall_delta=66.0) is True
    assert check_clock_drift(mono_delta=60.0, wall_delta=60.5) is False


def test_verdict_invalid_on_dead_measurement_apparatus():
    assert compute_run_verdict(backend_alive=False) == "INVALID"
    assert compute_run_verdict(ryu_alive=False) == "INVALID"


def test_verdict_invalid_when_majority_waves_unreliable():
    assert compute_run_verdict(waves_total=5, waves_unreliable=3) == "INVALID"
    assert compute_run_verdict(waves_total=5, waves_unreliable=2) != "INVALID"


def test_verdict_suspect_on_invalid_waves_or_clock_drift():
    assert compute_run_verdict(invalid_waves=1) == "SUSPECT"
    assert compute_run_verdict(clock_drift=True) == "SUSPECT"


def test_verdict_degraded_on_calibration_and_clean_otherwise():
    assert compute_run_verdict(calibration_status="degraded") == "DEGRADED"
    assert compute_run_verdict() == "CLEAN"


def test_report_eligible_verdicts():
    assert REPORT_ELIGIBLE == ("CLEAN", "DEGRADED")
