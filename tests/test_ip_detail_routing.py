"""RED tests: drawer routing, watchlist live vs audit historical.

Plan: notes/bugs/watchlist-audit-drawer-source-swap.md fix.
Watchlist clicks must serve live state even when flows are stale;
audit clicks address a specific session event, never live state.
Run: python3 -m pytest tests/test_ip_detail_routing.py -v
"""
import pytest

from backend.database import writer
from backend.mitigation import state_machine as sm
from backend.pipeline.flow_tracker import tracker


def _live_state(ip, session='sess-NEW'):
    return sm.IpState(
        src_ip=ip, phase=2, attack_vector='SYN Flood', if_score=0.71,
        confidence=0.85, priority='High', action_taken='Time Ban (5m)',
        ban_level=1, offence_count=3, session_id=session,
        peak_if_score=0.88, peak_confidence=0.92,
    )


def _client():
    from flask import Flask
    from backend.api import ip_detail
    app = Flask(__name__)
    app.register_blueprint(ip_detail.bp)
    return app.test_client()


@pytest.fixture()
def active_state(monkeypatch):
    from backend.api import ip_detail
    ip = '10.99.0.77'
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    sm.state_machine._states[ip] = _live_state(ip)
    monkeypatch.setattr(ip_detail.behavioral, 'get_decay_score', lambda i: 2.5)
    monkeypatch.setattr(ip_detail.behavioral, 'get_offence_count', lambda i: 3)
    monkeypatch.setattr(ip_detail, 'query', lambda *a, **k: [])
    yield ip
    sm.state_machine._states.pop(ip, None)
    tracker.remove_flow(ip)
    tracker.invalidate_cache(ip)


def test_active_stale_flow_serves_live_state_not_snapshot(active_state, monkeypatch):
    from backend.api import ip_detail
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: {
        'released_at': '2026-09-20 10:00:00',
        'reason': 'Time Ban expired',
        'payload': {'src_ip': ip, 'snapshot_marker': 'OLD-INCIDENT'},
    })
    res = _client().get(f'/api/ip_detail/{active_state}')
    assert res.status_code == 200
    data = res.get_json()
    assert data['is_live'] is True
    assert data.get('flow_stale') is True
    assert data['state']['phase'] == 2
    assert data['state']['action_taken'] == 'Time Ban (5m)'
    assert 'snapshot_at' not in data
    assert 'snapshot_marker' not in str(data)


def test_session_query_serves_clicked_event_not_live(monkeypatch):
    from backend.api import ip_detail
    rows = [{
        'timestamp': '2026-09-21 09:00:00', 'predicted_class': 'attack',
        'attack_vector': 'SYN Flood', 'confidence': 0.9, 'if_score': 0.8,
        'phase': 'Quarantined', 'priority': 'High', 'action_taken': 'Quarantined',
        'event_type': 'transition', 'reason': 'flood', 'session_id': 'sess-OLD',
    }]

    def _query(sql, params=()):
        if 'session_id' in ' '.join(sql.split()):
            return [dict(r) for r in rows]
        return []

    monkeypatch.setattr(ip_detail, '_is_active', lambda ip: True)
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    monkeypatch.setattr(ip_detail, 'query', _query)
    res = _client().get('/api/ip_detail/10.99.0.78?session_id=sess-OLD')
    assert res.status_code == 200
    data = res.get_json()
    assert data['is_live'] is False
    assert data.get('session_id') == 'sess-OLD'
    assert data['state']['action_taken'] == 'Quarantined'


def test_session_query_unknown_session_404s(monkeypatch):
    from backend.api import ip_detail
    monkeypatch.setattr(ip_detail, 'query', lambda *a, **k: [])
    res = _client().get('/api/ip_detail/10.99.0.79?session_id=nope')
    assert res.status_code == 404


def _legacy_rows():
    ev = {
        'timestamp': '2026-09-21 09:00:00', 'predicted_class': 'attack',
        'attack_vector': 'SYN Flood', 'confidence': 0.9, 'if_score': 0.8,
        'phase': 'Time Ban', 'priority': 'High', 'action_taken': 'Time Ban',
    }
    hist = {
        'ban_level': 1, 'phase_reached': 2, 'first_seen': '2026-09-21 08:00:00',
        'priority': 'High', 'offence_count': 2, 'reputation_score': 1.5,
        'unblocked_at': '2026-09-21 10:05:00',
    }
    return ev, hist


def test_legacy_historical_forces_not_live(monkeypatch):
    from backend.api import ip_detail
    ev, hist = _legacy_rows()

    def _query(sql, params=()):
        s = ' '.join(sql.split())
        if 'FROM detection_features' in s:
            return []
        if 'FROM ip_attack_history' in s:
            return [dict(hist)]
        if 'MAX(if_score)' in s:
            return []
        if 'attack_vector FROM' in s:
            return []
        if 'SELECT timestamp, phase, action_taken' in s:
            return []
        return [dict(ev)]

    monkeypatch.setattr(ip_detail, '_is_active', lambda ip: True)
    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    monkeypatch.setattr(ip_detail, 'query', _query)
    data = ip_detail._build_db_features('10.99.0.80', as_historical=True)
    assert data['is_live'] is False


def test_legacy_last_seen_from_unblocked_at(monkeypatch):
    from backend.api import ip_detail
    ev, hist = _legacy_rows()

    def _query(sql, params=()):
        s = ' '.join(sql.split())
        if 'FROM detection_features' in s:
            return []
        if 'FROM ip_attack_history' in s:
            return [dict(hist)]
        if 'MAX(if_score)' in s:
            return []
        if 'attack_vector FROM' in s:
            return []
        if 'SELECT timestamp, phase, action_taken' in s:
            return []
        return [dict(ev)]

    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    monkeypatch.setattr(ip_detail, 'query', _query)
    data = ip_detail._build_db_features('10.99.0.80')
    assert data['state']['last_seen'] == '2026-09-21 10:05:00'


def test_phase_label_variants_map_to_numeric(monkeypatch):
    from backend.api import ip_detail

    def _query_for(phase_label):
        ev = {
            'timestamp': '2026-09-21 09:00:00', 'predicted_class': 'attack',
            'attack_vector': 'SYN Flood', 'confidence': 0.9, 'if_score': 0.8,
            'phase': phase_label, 'priority': 'High', 'action_taken': 'x',
        }

        def _query(sql, params=()):
            s = ' '.join(sql.split())
            if 'FROM detection_features' in s:
                return []
            if 'FROM ip_attack_history' in s:
                return []
            if 'MAX(if_score)' in s:
                return []
            if 'attack_vector FROM' in s:
                return []
            if 'SELECT timestamp, phase, action_taken' in s:
                return []
            return [dict(ev)]

        return _query

    monkeypatch.setattr(writer, 'get_release_snapshot', lambda ip: None)
    for label, expected in [
        ('Phase 1 - Re-offence #3', 1),
        ('Phase 2', 2),
        ('Time Ban', 2),
        ('Blackhole', 3),
    ]:
        monkeypatch.setattr(ip_detail, 'query', _query_for(label))
        data = ip_detail._build_db_features('10.99.0.81')
        assert data['state']['phase'] == expected, label


def test_clear_all_snapshots_each_ip(monkeypatch):
    saved = []
    monkeypatch.setattr(sm.state_machine, '_push_command', lambda *a, **k: None)
    monkeypatch.setattr(
        sm.state_machine, '_snapshot_release',
        lambda ip, reason: saved.append(ip))
    monkeypatch.setattr(writer, 'delete_quarantine_state', lambda ip: None)
    sm.state_machine._states['10.99.0.91'] = _live_state('10.99.0.91')
    sm.state_machine._states['10.99.0.92'] = _live_state('10.99.0.92')
    try:
        cleared = sm.state_machine.clear_all_non_permanent()
    finally:
        sm.state_machine._states.pop('10.99.0.91', None)
        sm.state_machine._states.pop('10.99.0.92', None)
    assert cleared == 2
    assert sorted(saved) == ['10.99.0.91', '10.99.0.92']
