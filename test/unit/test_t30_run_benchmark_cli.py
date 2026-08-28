"""T30: benchmark runner CLI surface (simulation.run_benchmark).

Pins: module import stays side-effect free (topology/backend imported
lazily), pilot requires --out-dir (R5b), counted sessions refuse --attach,
naive-local CWD-independent default out-dir, model-artifact pre-flight
checks subdirectories too (models live in models/<family>/*.pkl).
"""
import pytest

from simulation.run_benchmark import (
    PROJECT_ROOT,
    SIM_DIR,
    _load_topology_module,
    build_default_out_dir,
    models_present,
    parse_args,
)


def test_load_topology_module_loads_file_not_namespace_package():
    # topology/ has no __init__.py, so a plain `import topology` yields an
    # empty namespace package. The loader must read topology/topology.py
    # directly and expose the real module attributes.
    from test_t29_helpers import load_topology_stubbed
    load_topology_stubbed("topology_loader_stub")  # installs mininet stubs
    mod = _load_topology_module()
    for attr in ("setLogLevel", "build_star", "start_server", "_warmup_macs",
                 "start_baseline_traffic", "_start_restore_poller",
                 "start_syn_flood_campaign", "start_mixed_campaign",
                 "flash_crowd", "stop_all_attacks"):
        assert hasattr(mod, attr), attr


def test_models_present_in_real_repo():
    assert models_present() is True


def test_models_present_false_for_empty_dir(tmp_path):
    assert models_present(tmp_path) is False


def test_models_present_true_for_nested_pkl(tmp_path):
    sub = tmp_path / "isolation_forest"
    sub.mkdir()
    (sub / "model.pkl").write_bytes(b"x")
    assert models_present(tmp_path) is True


def test_stale_mininet_state_detected_from_link_and_bridge_listing():
    from simulation.run_benchmark import _stale_mininet_state

    def fake_cmd(cmd):
        if "ip -o link" in cmd:
            return "4: s0-eth1: <BROADCAST,UP> ...\n5: s1-eth2: <BROADCAST,UP> ..."
        if "ovs-vsctl list-br" in cmd:
            return "s0\ns1\n"
        return ""

    stale = _stale_mininet_state(cmd_runner=fake_cmd)
    assert any("interface" in s for s in stale)
    assert any("OVS bridge" in s for s in stale)


def test_stale_mininet_state_clean_system_returns_empty():
    from simulation.run_benchmark import _stale_mininet_state

    def fake_cmd(cmd):
        if "ip -o link" in cmd:
            return "1: lo: ... 2: eth0: ..."
        return ""

    assert _stale_mininet_state(cmd_runner=fake_cmd) == []


def test_module_paths_are_cwd_independent():
    assert SIM_DIR == PROJECT_ROOT / "simulation"
    assert PROJECT_ROOT.name == "ADDOS-NEW"


def test_default_flags():
    args = parse_args([])
    assert args.duration == 3600
    assert args.out_dir is None
    assert args.no_frontend is False
    assert args.pilot is False
    assert args.seed is None


def test_pilot_requires_out_dir():
    with pytest.raises(SystemExit):
        parse_args(["--pilot"])
    args = parse_args(["--pilot", "--out-dir", "/tmp/x"])
    assert args.pilot is True


def test_attach_is_rejected_entirely():
    # In-process Mininet can never attach to an already-running stack; the
    # flag must hard-error in every mode instead of being silently ignored.
    with pytest.raises(SystemExit):
        parse_args(["--attach"])
    with pytest.raises(SystemExit):
        parse_args(["--attach", "--pilot", "--out-dir", "/tmp/x"])


def test_build_default_out_dir_is_timestamped_under_runs():
    d = build_default_out_dir()
    assert d.is_absolute()
    assert d.parent == SIM_DIR / "runs"
    assert len(d.name) >= 14  # YYYYMMDD-HHMMSS or similar sortable stamp


def test_autorecover_kills_leftover_stack_processes():
    from simulation.run_benchmark import autorecover_stack

    killed = []
    state = {"dead": False}

    def fake_cmd(cmd):
        if "pgrep -f" in cmd:
            return "" if state["dead"] else (
                "4242\n" if "backend.main" in cmd else "")
        return ""

    def killer(pids):
        killed.append(list(pids))
        state["dead"] = True

    actions = autorecover_stack(cmd_runner=fake_cmd, killer=killer,
                                log=lambda msg: None)
    assert killed == [[4242]]
    assert any("killed" in a for a in actions)
    assert not any("mn -c" in a for a in actions)


def test_autorecover_treats_vanished_process_as_already_dead():
    # pgrep can report a pid that exits before we kill it (Errno 3 race);
    # that is success, not a failure. First pgrep round reports the pid,
    # the kill raises ProcessLookupError, the re-probe reports clean.
    import pytest
    from simulation.run_benchmark import autorecover_stack

    state = {"n": 0}

    def fake_cmd(cmd):
        if "pgrep -f" in cmd and "backend.main" in cmd:
            state["n"] += 1
            return "4242\n" if state["n"] == 1 else ""
        return ""

    def killer(pids):
        raise ProcessLookupError("No such process")

    actions = autorecover_stack(cmd_runner=fake_cmd, killer=killer,
                                log=lambda msg: None)
    assert any("killed" in a for a in actions)


def test_autorecover_fails_when_killed_process_survives():
    from simulation.run_benchmark import autorecover_stack

    def fake_cmd(cmd):
        if "pgrep -f" in cmd and "backend.main" in cmd:
            return "4242\n"  # survives every kill attempt
        return ""

    with pytest.raises(SystemExit):
        autorecover_stack(cmd_runner=fake_cmd, killer=lambda pids: None,
                          log=lambda msg: None)


def test_autorecover_cleans_stale_mininet_state():
    from simulation.run_benchmark import autorecover_stack

    state = {"clean": False}

    def fake_cmd(cmd):
        if "mn -c" in cmd:
            state["clean"] = True
            return ""
        if "ip -o link" in cmd:
            return "" if state["clean"] else "4: s0-eth1: ..."
        return ""

    actions = autorecover_stack(cmd_runner=fake_cmd, killer=lambda pids: None,
                                log=lambda msg: None)
    assert state["clean"] is True
    assert any("mn -c" in a for a in actions)


def test_autorecover_fails_when_mn_c_does_not_help():
    import pytest
    from simulation.run_benchmark import autorecover_stack

    def fake_cmd(cmd):
        if "ip -o link" in cmd:
            return "4: s0-eth1: ..."   # stale forever, mn -c never fixes it
        return ""

    with pytest.raises(SystemExit):
        autorecover_stack(cmd_runner=fake_cmd, killer=lambda pids: None,
                          log=lambda msg: None)
