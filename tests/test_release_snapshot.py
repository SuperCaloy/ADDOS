"""RED tests: release-moment snapshot of the full live payload.

Plan: notes/tasks/release-snapshot-plan.md Phase 1.
Backend TDD only. Run: python3 -m pytest tests/test_release_snapshot.py -v
"""
import json
import threading
import time

import pytest

from backend.database import writer
from backend.mitigation import state_machine as sm
from backend.pipeline.flow_tracker import tracker


def _live_state(ip):
    return sm.IpState(
        src_ip=ip, phase=2, attack_vector='UDP Flood', if_score=0.64,
        confidence=0.8, priority='High', action_taken='Time Ban',
        ban_level=1, offence_count=2, session_id='abc123',
    )


def _seed_tracker(ip):
    tracker.update_flow(ip, {
        'packet_count': 5000, 'byte_count': 750000,
        'packet_count_per_second': 1200.0, 'byte_count_per_second': 180000.0,
        'flow_duration_sec': 30.0, 'bytes_per_packet': 150.0,
        'flow_count_per_src': 1, 'tp_src': 5000, 'tp_dst': 80, 'ip_proto': 17,
    })
    tracker.remember_verdict(ip, 0.64, True, 'UDP Flood', 0.8)


@pytest.fixture()
def clean_tracker():
    yield
    for ip in ('10.99.0.11', '10.99.0.12'):
        tracker.remove_flow(ip)
        tracker.invalidate_cache(ip)


def test_save_snapshot_upserts_full_payload(clean_tracker, monkeypatch):
    captured = {}

    def _capture(sql, params):
        captured['sql'] = sql
        captured['params'] = params

    monkeypatch.setattr(writer, 'execute', _capture)
    payload = {
        'src_ip': '10.99.0.11', 'is_live': True,
        'features': {'pps': 1200.0}, 'ml': {'attack_class': 'UDP Flood'},
        'state': {'phase': 2}, 'thresholds': {}, 'phase_history': [],
        'tea_ip_profile': {}, 'baselines': {}, 'deviations': {},
    }
    writer.save_release_snapshot('10.99.0.11', 'Time Ban expired', payload)
    assert 'ip_release_snapshot' in captured['sql']
    assert 'ON CONFLICT(src_ip)' in captured['sql']
    stored = json.loads(captured['params'][3])
    for section in ('features', 'ml', 'state', 'thresholds',
                    'phase_history', 'tea_ip_profile', 'baselines', 'deviations'):
        assert section in stored, section


def test_clear_snapshots_final_live_frame(clean_tracker, monkeypatch):
    ip = '10.99.0.11'
    _seed_tracker(ip)
    saved = {}
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    monkeypatch.setattr(writer, 'save_release_snapshot',
                        lambda src, reason, payload: saved.update(
                            {'src': src, 'reason': reason, 'payload': payload}))
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    import backend.pipeline.decision_engine as de
    monkeypatch.setattr(de, '_push_sse_event', lambda *a, **k: None)
    sm.state_machine._states[ip] = _live_state(ip)
    sm.state_machine._clear(ip, reason='Time Ban expired')
    assert saved['src'] == ip
    assert saved['reason'] == 'Time Ban expired'
    assert saved['payload']['features']['pkt_count'] == 5000
    assert saved['payload']['ml']['attack_class'] == 'UDP Flood'
    assert 'tea_ip_profile' in saved['payload']


def test_clear_without_scored_flow_skips_snapshot(clean_tracker, monkeypatch):
    ip = '10.99.0.12'
    saved = []
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    monkeypatch.setattr(writer, 'save_release_snapshot',
                        lambda *a: saved.append(a))
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    import backend.pipeline.decision_engine as de
    monkeypatch.setattr(de, '_push_sse_event', lambda *a, **k: None)
    sm.state_machine._states[ip] = _live_state(ip)
    sm.state_machine._clear(ip, reason='Time Ban expired')
    assert saved == []
    assert ip not in sm.state_machine._states


def test_db_endpoint_prefers_snapshot(monkeypatch):
    from backend.api import ip_detail
    payload = {
        'src_ip': '10.99.0.11', 'is_live': True,
        'features': {'pps': 1200.0, 'pkt_count': 5000},
        'ml': {'attack_class': 'UDP Flood', 'if_score': 0.64,
               'confidence': 80.0, 'is_anomaly': True},
        'state': {'phase': 2, 'priority': 'High'},
        'thresholds': {}, 'phase_history': [{'phase': 2}],
        'tea_ip_profile': {'verdict': 'attack'},
        'baselines': {}, 'deviations': {'pps': 26.3},
    }
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: {
        'released_at': '2026-09-10 18:00:00',
        'reason': 'Time Ban expired',
        'payload': payload,
    })
    data = ip_detail._build_db_features('10.99.0.11')
    assert data['is_live'] is False
    assert data['snapshot_at'] == '2026-09-10 18:00:00'
    assert data['features']['pps'] == 1200.0
    assert data['ml']['attack_class'] == 'UDP Flood'
    assert data['deviations'] == {'pps': 26.3}
    assert data['tea_ip_profile'] == {'verdict': 'attack'}
    assert data['phase_history'] == [{'phase': 2}]


def test_db_endpoint_falls_back_without_snapshot(monkeypatch):
    from backend.api import ip_detail
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    assert ip_detail._build_db_features('10.99.0.250') is None


def test_flask_client_prefers_snapshot_when_present(monkeypatch):
    from flask import Flask
    from backend.api import ip_detail
    app = Flask(__name__)
    app.register_blueprint(ip_detail.bp)
    client = app.test_client()

    monkeypatch.setattr(ip_detail, '_is_active', lambda ip: False)
    payload = {
        'src_ip': '10.99.0.11', 'is_live': True,
        'features': {'pps': 1200.0}, 'ml': {'attack_class': 'UDP Flood'},
    }
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: {
        'released_at': '2026-09-10 18:00:00',
        'reason': 'Time Ban expired',
        'payload': payload,
    })
    res = client.get('/api/ip_detail/10.99.0.11')
    assert res.status_code == 200
    data = res.get_json()
    assert data['is_live'] is False
    assert data['snapshot_at'] == '2026-09-10 18:00:00'
    assert data['release_reason'] == 'Time Ban expired'
    assert data['features']['pps'] == 1200.0


def test_flask_client_falls_back_when_no_snapshot(monkeypatch):
    from flask import Flask
    from backend.api import ip_detail
    app = Flask(__name__)
    app.register_blueprint(ip_detail.bp)
    client = app.test_client()

    monkeypatch.setattr(ip_detail, '_is_active', lambda ip: False)
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    monkeypatch.setattr(ip_detail, 'query', lambda *a, **k: [])

    res = client.get('/api/ip_detail/10.99.0.250')
    assert res.status_code == 404


def test_tick_release_snapshots_without_deadlock(clean_tracker, monkeypatch):
    ip = '10.99.0.11'
    _seed_tracker(ip)
    saved = {}
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    monkeypatch.setattr(writer, 'save_release_snapshot',
                        lambda src, reason, payload: saved.update(
                            {'src': src, 'reason': reason, 'payload': payload}))
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    import backend.pipeline.decision_engine as de
    monkeypatch.setattr(de, '_push_sse_event', lambda *a, **k: None)
    sm.state_machine._states[ip] = sm.IpState(
        src_ip=ip, phase=1, phase_entered=time.monotonic() - 100.0,
        attack_vector='UDP Flood', if_score=0.1, confidence=0.8,
        priority='Low', action_taken='Quarantined', recent_pps=0.0,
    )
    t = threading.Thread(target=sm.state_machine.tick, daemon=True)
    t.start()
    t.join(timeout=1.0)
    assert not t.is_alive(), 'state_machine.tick() deadlocked during release snapshot'
    assert saved.get('src') == ip
    assert saved.get('reason') == 'Attack Stopped'
    assert 'features' in saved.get('payload', {})


def test_ban_expiry_saves_snapshot(clean_tracker, monkeypatch):
    ip = '10.99.0.11'
    _seed_tracker(ip)
    saved = {}
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    monkeypatch.setattr(writer, 'save_release_snapshot',
                        lambda src, reason, payload: saved.update(
                            {'src': src, 'reason': reason, 'payload': payload}))
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    import backend.pipeline.decision_engine as de
    monkeypatch.setattr(de, '_push_sse_event', lambda *a, **k: None)
    sm.state_machine._states[ip] = sm.IpState(
        src_ip=ip, phase=2, phase_entered=time.monotonic() - 200.0,
        ttl_expires_at=time.monotonic() - 10.0,
        attack_vector='UDP Flood', if_score=0.1, confidence=0.8,
        priority='High', action_taken='Time Ban', recent_pps=0.0,
    )
    sm.state_machine.tick()
    assert saved.get('src') == ip
    assert saved.get('reason') == 'Time Ban Expired'
    assert 'features' in saved.get('payload', {})


def test_manual_release_saves_snapshot(clean_tracker, monkeypatch):
    ip = '10.99.0.11'
    _seed_tracker(ip)
    saved = {}
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    monkeypatch.setattr(writer, 'save_release_snapshot',
                        lambda src, reason, payload: saved.update(
                            {'src': src, 'reason': reason, 'payload': payload}))
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    import backend.pipeline.decision_engine as de
    monkeypatch.setattr(de, '_push_sse_event', lambda *a, **k: None)
    sm.state_machine._states[ip] = sm.IpState(
        src_ip=ip, phase=2, attack_vector='UDP Flood', if_score=0.8,
        confidence=0.9, priority='High', action_taken='Time Ban',
    )
    ok = sm.state_machine.manual_release(ip)
    assert ok is True
    assert saved.get('src') == ip
    assert saved.get('reason') == 'Manual Release'
    assert 'features' in saved.get('payload', {})


def test_endpoint_serves_snapshot_when_historical_requested_even_if_active(monkeypatch):
    from flask import Flask
    from backend.api import ip_detail
    app = Flask(__name__)
    app.register_blueprint(ip_detail.bp)
    client = app.test_client()

    monkeypatch.setattr(ip_detail, '_is_active', lambda ip: True)
    monkeypatch.setattr(ip_detail, '_build_live_features', lambda ip: {
        'src_ip': ip, 'is_live': True, 'features': {'pps': 9999.0},
    })
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: {
        'released_at': '2026-09-10 19:19:13',
        'reason': 'Time Ban Expired',
        'payload': {'src_ip': ip, 'is_live': True, 'features': {'pps': 50.0}},
    })

    # Default request without flag returns live
    res_live = client.get('/api/ip_detail/10.99.0.11')
    assert res_live.status_code == 200
    assert res_live.get_json()['is_live'] is True
    assert res_live.get_json()['features']['pps'] == 9999.0

    # Request with historical=1 returns the release snapshot
    res_hist = client.get('/api/ip_detail/10.99.0.11?historical=1')
    assert res_hist.status_code == 200
    data = res_hist.get_json()
    assert data['is_live'] is False
    assert data['snapshot_at'] == '2026-09-10 19:19:13'
    assert data['release_reason'] == 'Time Ban Expired'
    assert data['features']['pps'] == 50.0


def test_flow_tracker_tracks_peaks_across_downgrades(clean_tracker):
    ip = '10.99.0.12'
    # Initial severe attack score
    tracker.remember_verdict(ip, 0.88, True, 'UDP Flood', 0.95)
    peak = tracker.get_peak(ip)
    assert peak is not None
    assert peak['if_score'] == 0.88
    assert peak['confidence'] == 0.95
    assert peak['attack_class'] == 'UDP Flood'

    # Traffic subsides: lower confidence and decayed IF score arrives
    tracker.remember_verdict(ip, 0.42, False, 'Normal', 0.65)
    peak2 = tracker.get_peak(ip)
    assert peak2['if_score'] == 0.88
    assert peak2['confidence'] == 0.95
    assert peak2['attack_class'] == 'UDP Flood'


def test_ip_state_tracks_peak_scores_and_to_api_dict_preserves_peak():
    state = sm.IpState(
        src_ip='10.99.0.12', phase=1, attack_vector='SYN Flood',
        if_score=0.82, confidence=0.91, priority='High',
    )
    assert state.peak_if_score == 0.82
    assert state.peak_confidence == 0.91

    # Simulate observation decay and low confidence update
    state.if_score = 0.40
    state.confidence = 0.60
    api_dict = state.to_api_dict()
    assert api_dict['if_score'] == 0.82
    assert api_dict['confidence'] == 91.0


def test_live_features_exposes_peak_scores_in_ml_dict(clean_tracker):
    from backend.api import ip_detail
    ip = '10.99.0.12'
    tracker.update_flow(ip, {
        'packet_count': 1000, 'byte_count': 100000,
        'packet_count_per_second': 500.0, 'byte_count_per_second': 50000.0,
        'flow_duration_sec': 10.0, 'bytes_per_packet': 100.0,
        'flow_count_per_src': 1, 'tp_src': 1234, 'tp_dst': 80, 'ip_proto': 6,
    })
    # Peak at 0.90 / 0.96
    tracker.remember_verdict(ip, 0.90, True, 'SYN Flood', 0.96)
    # Subsequent calm verdict at 0.45 / 0.65
    tracker.remember_verdict(ip, 0.45, False, 'Normal', 0.65)

    data = ip_detail._build_live_features(ip)
    assert data is not None
    assert data['ml']['if_score'] == 0.90
    assert data['ml']['confidence'] == 96.0
    assert data['ml']['attack_class'] == 'SYN Flood'


