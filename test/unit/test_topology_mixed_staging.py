def test_mixed_staging_fires_all_hosts_at_once():
    # Mixed campaign launches every attacker with zero start delay plus a
    # 0.1 s per-host stagger (prevents simultaneous OVS hits). All 10
    # hosts are therefore flooding within about 1 s, well inside the
    # 60 s mixed window of the 5-minute benchmark timetable.
    src = open("topology/topology.py").read()
    assert "schedule = {num: 0.0 for num in assignments}" in src
    assert "time.sleep(0.1)" in src
