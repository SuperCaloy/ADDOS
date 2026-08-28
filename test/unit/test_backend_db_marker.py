"""Benchmark DB auto-switch: marker file + /api/db_path confirmation.

Flow: run_benchmark writes benchmark/DB_TARGET; a backend started while the
marker exists boots onto the benchmark DB; /api/db_path lets the benchmark
confirm the switch before starting the timeline. Env var still wins.
"""
import importlib
import os


def test_config_env_var_wins_over_marker(tmp_path, monkeypatch):
    import backend.config as c
    marker = tmp_path / "DB_TARGET"
    marker.write_text(str(tmp_path / "marker.db"))
    monkeypatch.setattr(c, "MARKER_PATH", str(marker))
    monkeypatch.setenv("DDOS_DB_PATH", str(tmp_path / "env.db"))
    assert c._resolve_db_path() == str(tmp_path / "env.db")


def test_config_marker_file_selects_benchmark_db(tmp_path, monkeypatch):
    import backend.config as c
    marker = tmp_path / "DB_TARGET"
    marker.write_text(str(tmp_path / "marker.db"))
    monkeypatch.setattr(c, "MARKER_PATH", str(marker))
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    assert c._resolve_db_path() == str(tmp_path / "marker.db")


def test_config_defaults_to_logs_when_no_env_no_marker(tmp_path, monkeypatch):
    import backend.config as c
    monkeypatch.setattr(c, "MARKER_PATH", str(tmp_path / "missing" / "DB_TARGET"))
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    assert c._resolve_db_path().endswith("logs/ddos.db")


def test_config_db_path_computed_at_import_uses_resolver(tmp_path, monkeypatch):
    # reload with a marker pointed at via DDOS_DB_MARKER: module-level
    # DB_PATH must equal the marker target (backend boots onto benchmark db)
    import backend.config as c
    marker = tmp_path / "DB_TARGET"
    marker.write_text(str(tmp_path / "boot.db"))
    monkeypatch.setenv("DDOS_DB_MARKER", str(marker))
    monkeypatch.delenv("DDOS_DB_PATH", raising=False)
    c = importlib.reload(c)
    assert str(c.DB_PATH) == str(tmp_path / "boot.db")
    monkeypatch.delenv("DDOS_DB_MARKER", raising=False)
    importlib.reload(c)


def test_api_db_path_reports_backend_db(temp_db):
    from flask import Flask
    from backend.api.stats import bp
    from backend.config import DB_PATH

    app = Flask(__name__)
    app.register_blueprint(bp)
    resp = app.test_client().get("/api/db_path")
    assert resp.status_code == 200
    assert resp.get_json()["db_path"] == str(DB_PATH)
