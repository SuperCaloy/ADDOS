"""RED tests: frozen detection snapshot for session views plus stale blackhole.

Plan: notes/tasks/expert-trace-live-refresh-plan.md Section 9 Task 1 plus backend half of Task 3.
Run: python3 -m pytest tests/test_session_features_freeze.py -v
"""
import pytest

from backend.database import writer
from backend.mitigation import state_machine as sm

FLOOD_TS = "2026-09-21 09:00:00"
CALM_TS = "2026-09-21 10:00:00"
TEST_IP = "10.0.0.99"
BLACKHOLE_IP = "10.0.0.98"


def _session_rows():
    return [{
        "timestamp": FLOOD_TS, "predicted_class": "attack",
        "attack_vector": "SYN Flood", "confidence": 0.9, "if_score": 0.8,
        "phase": "Quarantined", "priority": "High", "action_taken": "Quarantined",
        "event_type": "transition", "reason": "flood", "session_id": "sess-1",
    }]


def _flood_feat():
    return {
        "packet_count": 950000, "byte_count": 142500000,
        "packet_count_per_second": 95000.0, "byte_count_per_second": 14250000.0,
        "flow_duration_sec": 10.0, "flags": 2, "bytes_per_packet": 150.0,
        "flow_count_per_src": 1, "tp_src": 5000, "tp_dst": 80, "ip_proto": 6,
    }


def _calm_feat():
    return {
        "packet_count": 1200, "byte_count": 180000,
        "packet_count_per_second": 12.0, "byte_count_per_second": 1800.0,
        "flow_duration_sec": 100.0, "flags": 2, "bytes_per_packet": 150.0,
        "flow_count_per_src": 1, "tp_src": 80, "tp_dst": 443, "ip_proto": 6,
    }


def _client():
    from flask import Flask
    from backend.api import ip_detail
    app = Flask(__name__)
    app.register_blueprint(ip_detail.bp)
    return app.test_client()


def test_session_features_use_event_time_row(monkeypatch):
    from backend.api import ip_detail

    def _query(sql, params=()):
        s = " ".join(sql.split())
        if "FROM mitigation_events" in s and "session_id" in s:
            return [dict(r) for r in _session_rows()]
        if "FROM detection_features" in s:
            if "ABS" in s or "strftime" in s:
                if len(params) == 2 and params[1] == FLOOD_TS:
                    return [dict(_flood_feat())]
                return [dict(_flood_feat())]
            return [dict(_calm_feat())]
        if "FROM ip_attack_history" in s:
            return []
        if "SELECT timestamp, phase, action_taken" in s:
            return [dict(r) for r in _session_rows()]
        return []

    monkeypatch.setattr(ip_detail, "query", _query)
    monkeypatch.setattr(writer, "get_release_snapshot", lambda ip: None)

    res = _client().get(
        "/api/ip_detail/%s?session_id=sess-1&timestamp=%s"
        % (TEST_IP, FLOOD_TS.replace(" ", "%20").replace(":", "%3A")))
    assert res.status_code == 200
    body = res.get_json()
    assert body["features"]["pkt_count"] == 950000
    assert body["snapshot_at"] == FLOOD_TS


def test_stale_blackhole_serves_live_last_observed_features(monkeypatch):
    from backend.api import ip_detail

    flood = _flood_feat()

    def _query(sql, params=()):
        s = " ".join(sql.split())
        if "FROM detection_features" in s:
            return [dict(flood)]
        if "FROM mitigation_events" in s or "FROM mitigation_events_archive" in s:
            return []
        if "FROM ip_attack_history" in s:
            return []
        return []

    monkeypatch.setattr(ip_detail, "query", _query)
    monkeypatch.setattr(ip_detail, "_is_active", lambda ip: True)
    monkeypatch.setattr(ip_detail, "_build_live_features", lambda ip: None)
    monkeypatch.setattr(
        ip_detail.behavioral, "get_decay_score", lambda ip: 2.5)
    monkeypatch.setattr(
        ip_detail.behavioral, "get_offence_count", lambda ip: 3)
    state = sm.IpState(
        src_ip=BLACKHOLE_IP, phase=3, attack_vector="SYN Flood",
        if_score=0.9, confidence=0.95, priority="Critical",
        action_taken="Blackhole", session_id="sess-bh",
    )
    monkeypatch.setattr(
        sm.state_machine, "get_state", lambda ip: state if ip == BLACKHOLE_IP else None)
    monkeypatch.setattr(writer, "get_release_snapshot", lambda ip: {
        "released_at": FLOOD_TS,
        "reason": "Blackhole active",
        "payload": {
            "src_ip": ip, "is_live": True,
            "features": {"pkt_count": 1, "pps": 1.0},
            "ml": {"attack_class": "OLD-INCIDENT", "if_score": 0.1,
                   "confidence": 10.0, "is_anomaly": True},
            "state": {"phase": 1, "priority": "Low"},
            "thresholds": {}, "phase_history": [],
            "tea_ip_profile": {"verdict": "attack"},
            "baselines": {}, "deviations": {"pps": 0.0},
        },
    })

    res = _client().get("/api/ip_detail/%s" % BLACKHOLE_IP)
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_live"] is True
    assert data.get("flow_stale") is True
    assert data["state"]["phase"] == 3
    assert data["state"]["action_taken"] == "Blackhole"
    assert data["features"]["pkt_count"] == 950000
    assert data["features"]["pps"] == 95000.0
    assert data["features"]["byte_count"] == 142500000
    assert "snapshot_at" not in data
    assert "OLD-INCIDENT" not in str(data)
