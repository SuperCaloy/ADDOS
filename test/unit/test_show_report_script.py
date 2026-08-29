"""benchmark/show_report.sh: temporary marker so the report shows benchmark data.

The script boots nothing by itself unless SHOW_REPORT_BACKEND_CMD is set; it
writes the DB marker, prints instructions, waits for Enter, then removes the
marker so normal backend starts return to logs/ddos.db.
"""
import os
import subprocess
import textwrap


def _setup_script(tmp_path):
    # copy the real script into a sandbox root so ROOT/marker/DB paths all
    # resolve inside tmp_path and repo state is never touched
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    src = os.path.join(repo, "benchmark", "show_report.sh")
    bench = tmp_path / "benchmark"
    bench.mkdir(exist_ok=True)
    dst = bench / "show_report.sh"
    dst.write_text(open(src).read())
    return dst


def _run(script, stdin="\n", env_extra=None, timeout=30):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        ["bash", str(script)], input=stdin.encode(), env=env,
        capture_output=True, timeout=timeout)


def test_script_writes_marker_during_and_removes_after(tmp_path):
    script = _setup_script(tmp_path)
    (tmp_path / "benchmark" / "benchmark.db").write_bytes(b"x")
    marker = tmp_path / "benchmark" / "DB_TARGET"
    seen = tmp_path / "seen.txt"
    env_extra = {
        "SHOW_REPORT_BACKEND_CMD":
            f'sh -c \'[ -f "{marker}" ] && echo yes > "{seen}"\'',
    }
    r = _run(script, env_extra=env_extra)
    assert r.returncode == 0, r.stderr.decode()
    assert seen.read_text().strip() == "yes", "marker must exist mid-run"
    assert not marker.exists(), "marker must be removed on exit"


def test_script_prints_report_instructions(tmp_path):
    script = _setup_script(tmp_path)
    (tmp_path / "benchmark" / "benchmark.db").write_bytes(b"x")
    r = _run(script, env_extra={"SHOW_REPORT_BACKEND_CMD": "true"})
    out = r.stdout.decode()
    assert "report" in out.lower()
    assert "restart the backend" in out.lower()
    assert "logs/ddos.db" in out  # restore reminder present


def test_script_refuses_when_benchmark_db_missing(tmp_path):
    script = _setup_script(tmp_path)
    r = _run(script, env_extra={"SHOW_REPORT_BACKEND_CMD": "true"})
    out = r.stdout.decode()
    assert "not found" in out.lower()
    assert r.returncode == 1
    marker = tmp_path / "benchmark" / "DB_TARGET"
    assert not marker.exists(), "no marker may be left behind on abort"


def test_script_with_real_db_proceeds(tmp_path):
    script = _setup_script(tmp_path)
    (tmp_path / "benchmark" / "benchmark.db").write_bytes(b"x")
    r = _run(script, env_extra={"SHOW_REPORT_BACKEND_CMD": "true"})
    assert r.returncode == 0, r.stderr.decode()
    assert "not found" not in r.stdout.decode().lower()
