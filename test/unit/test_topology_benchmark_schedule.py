from unittest import mock

import pytest


@pytest.fixture
def fast_clock(monkeypatch):
    # Virtual clock: sleeps advance time instantly so a 300 s session
    # runs in milliseconds. Patching is auto-undone after each test.
    import topology.benchmark as b
    now = [1000.0]

    def _sleep(s):
        now[0] += s

    monkeypatch.setattr(b.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(b.time, "sleep", _sleep)
    return now


def _mock_topo(calls, advance=None):
    topo = mock.MagicMock()
    topo._ATTACKER_NUMS = set(range(16, 26))
    topo._LEGIT_NUMS = set(range(1, 16))
    topo.start_syn_flood_campaign.side_effect = lambda: calls.append("syn")
    topo.start_icmp_flood_campaign.side_effect = lambda: calls.append("icmp")
    topo.start_udp_flood_campaign.side_effect = lambda: calls.append("udp")
    topo.start_mixed_campaign.side_effect = lambda: calls.append("mixed")
    topo.stop_all_attacks.side_effect = lambda: calls.append("stop")
    if advance:
        topo.start_udp_flood_campaign.side_effect = advance
    return topo


def _run_one(b, topo, tmp_path, monkeypatch):
    monkeypatch.setattr(b, "_marker_path", lambda: tmp_path / "DB_TARGET")
    noop_gate = lambda topo, cap_s: None
    noop_reset = lambda topo: None
    try:
        b.run(topo, net=mock.MagicMock(), hosts=[], duration_s=300,
              sessions=1, calibration_gate=noop_gate, reset_fn=noop_reset,
              db_gate=lambda t, cap_s: None)
    except SystemExit:
        pass


def test_timetable_totals_300s_with_fixed_bounds():
    import topology.benchmark as b
    total = sum(d for _, _, _, d in b._PHASES_300)
    assert total == 300
    assert b._PHASES_300[0][0] == 0
    last_start, _, _, last_dur = b._PHASES_300[-1]
    assert last_start + last_dur == 300
    kinds = [(k, a) for _, k, a, _ in b._PHASES_300]
    assert kinds == [("benign", None), ("wave", "syn"), ("wave", "udp"),
                     ("wave", "icmp"), ("quiet", None), ("wave", "mixed")]


def test_schedule_fires_expected_campaigns_in_order(tmp_path, monkeypatch,
                                                   fast_clock):
    import topology.benchmark as b
    calls = []
    topo = _mock_topo(calls)
    monkeypatch.setattr(b, "_clean_poll_gate", lambda topo, limit: None)
    _run_one(b, topo, tmp_path, monkeypatch)
    # expected sequence of wave starts, in order
    waves = [c for c in calls if c in ("syn", "icmp", "udp", "mixed")]
    assert waves == ["syn", "udp", "icmp", "mixed"], waves
    # stop called on the quiet window AND unconditionally at the end
    assert calls.count("stop") >= 2, calls
    assert calls[-1] == "stop"


def test_run_prints_per_step_progress_lines(capsys, tmp_path, monkeypatch,
                                            fast_clock):
    import re
    import topology.benchmark as b
    calls = []
    topo = _mock_topo(calls)
    monkeypatch.setattr(b, "_clean_poll_gate", lambda topo, limit: None)
    _run_one(b, topo, tmp_path, monkeypatch)
    out = capsys.readouterr().out
    steps = re.findall(r"step (\d+)/6", out)
    # every step appears twice: the start line and the "(still on)" echo
    assert steps == [str(n) for n in range(1, 7) for _ in range(2)], steps
    assert out.count("still on") == 6, out.count("still on")
    # every line carries the eval-clock stamp of its phase start (MM:SS)
    assert "T+00:00/05:00" in out
    assert "T+02:00/05:00" in out
    assert "T+04:00/05:00" in out
    # wave and phase labels are human readable and in timeline order
    labels = ["benign baseline", "SYN wave", "UDP wave", "ICMP wave",
              "quiet window", "mixed wave"]
    pos = [out.index(lbl) for lbl in labels]
    assert pos == sorted(pos), list(zip(labels, pos))
    # teardown line tells the operator the run ended and reset ran
    assert "stopping attacks" in out


def test_session_deadline_skips_late_phases_but_still_stops(
        tmp_path, monkeypatch, fast_clock):
    import topology.benchmark as b
    calls = []

    def slow_udp():
        calls.append("udp")
        fast_clock[0] += 400  # blow past the 5:00 deadline mid-session

    topo = _mock_topo(calls, advance=slow_udp)
    monkeypatch.setattr(b, "_clean_poll_gate", lambda topo, limit: None)
    _run_one(b, topo, tmp_path, monkeypatch)
    waves = [c for c in calls if c in ("syn", "icmp", "udp", "mixed")]
    assert waves == ["syn", "udp"], waves  # icmp and mixed never fire
    assert calls.count("stop") >= 2, calls  # session + final stops still run
    assert calls[-1] == "stop"


def test_run_rejects_non_300s_duration_without_doubles():
    import topology.benchmark as b
    try:
        b.run(mock.MagicMock(), net=mock.MagicMock(), hosts=[],
              duration_s=12)
    except ValueError:
        return
    except SystemExit:
        pass
    raise AssertionError("expected ValueError for duration_s != 300")
