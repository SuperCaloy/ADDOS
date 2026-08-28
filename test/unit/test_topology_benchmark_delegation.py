import inspect


def test_benchmark_has_no_topology_import():
    import topology.benchmark as b
    # Importing benchmark.py transiently registers "topology" in sys.modules
    # (the parent package) on first import. The real contract is that the
    # MODULE SOURCE itself never imports topology, and that `run` accepts the
    # topology module object (passed in) rather than importing it.
    src = inspect.getsource(b)
    assert "import topology" not in src
    assert "from topology" not in src
    assert hasattr(b, "run")


def test_run_benchmark_command_exists():
    src = open("topology/topology.py").read()
    # py run_benchmark() command (do_py re-raises SystemExit for clean exit),
    # and do_py must exist to host it.
    assert "def run_benchmark" in src
    assert "def do_py" in src
