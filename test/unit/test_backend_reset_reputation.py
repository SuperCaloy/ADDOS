"""POST /api/admin/reset_reputation must clear live in-memory reputation.

Deleting DB episode rows under a live backend is not enough: writer's
reputation timestamp cache and the state machine's IpState registry survive
until restart, so the next benchmark session would not be ground truth.
"""
import pytest

from backend.database import writer
from backend.mitigation.state_machine import IpState, state_machine


@pytest.fixture()
def client(temp_db):
    from flask import Flask
    from backend.api.mitigation import bp

    app = Flask(__name__)
    app.register_blueprint(bp)
    return app.test_client()


def test_reset_endpoint_clears_writer_cache_and_state_machine(client):
    writer._reputation_cache["10.9.9.1"] = ["2026-08-25 10:00:00"]
    state_machine._states["10.9.9.1"] = IpState(src_ip="10.9.9.1")
    state_machine._sinkhole_history["10.9.9.1"] = 2

    resp = client.post("/api/admin/reset_reputation")

    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}
    assert writer._reputation_cache == {}
    assert state_machine._states == {}
    assert state_machine._sinkhole_history == {}


def test_reset_endpoint_is_safe_on_empty_state(client):
    resp = client.post("/api/admin/reset_reputation")

    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}
