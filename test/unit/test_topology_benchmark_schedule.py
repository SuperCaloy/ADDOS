from unittest import mock


def test_schedule_fires_expected_campaigns_in_order(tmp_path, monkeypatch):
    import topology.benchmark as b
    monkeypatch.setattr(b, "_marker_path", lambda: tmp_path / "DB_TARGET")
    topo = mock.MagicMock()
    topo._ATTACKER_NUMS = set(range(6, 20)) | {22}
    topo._RETIRED_NUMS = {23, 24, 25, 26, 27}
    topo._LEGIT_NUMS = set(range(1, 6))
    calls = []
    topo.start_syn_flood_campaign.side_effect = lambda: calls.append("syn")
    topo.start_icmp_flood_campaign.side_effect = lambda: calls.append("icmp")
    topo.start_udp_flood_campaign.side_effect = lambda: calls.append("udp")
    topo.start_mixed_campaign.side_effect = lambda: calls.append("mixed")
    topo.stop_all_attacks.side_effect = lambda: calls.append("stop")
    # short duration + stubs so the test runs in seconds, not 60 minutes
    noop_gate = lambda topo, cap_s: None
    noop_reset = lambda topo: None
    # run() ends with SystemExit(0) per the Task 1 interface contract, so
    # catch it here and assert on the recorded call sequence.
    try:
        b.run(topo, net=mock.MagicMock(), hosts=[], duration_s=12,
              calibration_gate=noop_gate, reset_fn=noop_reset)
    except SystemExit:
        pass
    # expected sequence of wave starts, in order
    waves = [c for c in calls if c in ("syn", "icmp", "udp", "mixed")]
    assert waves == ["syn", "icmp", "udp", "mixed", "mixed"], waves
    # stop called after every calm window (settle + 4 quiet + recover = 6)
    # AND unconditionally at the end via the finally -> at least 7
    assert calls.count("stop") >= 7, calls
    assert calls[-1] == "stop"


def test_run_prints_per_step_progress_lines(capsys, tmp_path, monkeypatch):
    import re
    import topology.benchmark as b
    monkeypatch.setattr(b, "_marker_path", lambda: tmp_path / "DB_TARGET")
    topo = mock.MagicMock()
    noop_gate = lambda topo, cap_s: None
    noop_reset = lambda topo: None
    try:
        b.run(topo, net=mock.MagicMock(), hosts=[], duration_s=12,
              calibration_gate=noop_gate, reset_fn=noop_reset,
              db_gate=lambda t, cap_s: None)
    except SystemExit:
        pass
    out = capsys.readouterr().out
    steps = re.findall(r"step (\d+)/13", out)
    # every step appears twice: the start line and the "(still on)" echo
    assert steps == [str(n) for n in range(1, 14) for _ in range(2)], steps
    # after every phase (e.g. noisy stop_all_attacks output) the benchmark
    # re-echoes its status so the newest line is always the current one
    assert out.count("still on") == 13, out.count("still on")
    # every line carries the eval-clock stamp of its phase start (MM:SS);
    # 12s total renders as /00:12 and the SYN wave starts at 9/60 of 12s
    assert "T+00:00/00:12" in out
    assert "T+00:02/00:12" in out
    # wave and phase labels are human readable and in timeline order
    labels = ["baseline soak", "flash-crowd FP probe", "settle", "SYN wave",
              "quiet window", "ICMP wave", "UDP wave", "mixed wave A",
              "mixed wave B", "recovery observation"]
    pos = [out.index(lbl) for lbl in labels]
    assert pos == sorted(pos), list(zip(labels, pos))
    # teardown line tells the operator the run ended and reset ran
    assert "stopping attacks" in out and "reset" in out
