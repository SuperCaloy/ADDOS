"""RED tests: degrading live endpoint serves flow without fresh cache.

Plan: notes/tasks/live-drawer-reliability-plan.md Phase 2.
Run: python3 -m pytest tests/test_live_endpoint.py -v
"""
import time

import pytest

from backend.pipeline.flow_tracker import tracker
from backend.api import ip_detail


FLOW_STATS = {
    'packet_count': 5000, 'byte_count': 750000,
    'packet_count_per_second': 1200.0, 'byte_count_per_second': 180000.0,
    'flow_duration_sec': 30.0, 'bytes_per_packet': 150.0,
    'flow_count_per_src': 1, 'tp_src': 5000, 'tp_dst': 80, 'ip_proto': 17,
}


@pytest.fixture()
def live_ip():
    ip = '10.99.0.1'
    tracker.update_flow(ip, dict(FLOW_STATS))
    yield ip
    tracker.remove_flow(ip)
    tracker.invalidate_cache(ip)


def test_flow_without_cache_serves_stale_verdict(live_ip):
    tracker.invalidate_cache(live_ip)
    tracker.remember_verdict(live_ip, 0.64, True, 'UDP Flood', 0.8)
    data = ip_detail._build_live_features(live_ip)
    assert data is not None
    assert data['is_live'] is True
    assert data['ml']['stale'] is True
    assert data['ml']['attack_class'] == 'UDP Flood'
    assert data['features']['pkt_count'] == 5000


def test_flow_with_fresh_cache_is_not_stale(live_ip):
    tracker.set_cache(live_ip, 0.64, True, 'UDP Flood', 0.8)
    data = ip_detail._build_live_features(live_ip)
    assert data['ml']['stale'] is False
    assert data['ml']['attack_class'] == 'UDP Flood'


def test_missing_flow_returns_none():
    assert ip_detail._build_live_features('10.99.0.250') is None


def test_stale_flow_returns_none(live_ip, monkeypatch):
    tracker.remember_verdict(live_ip, 0.64, True, 'UDP Flood', 0.8)
    entry = tracker.get_flow(live_ip)
    entry.last_seen -= 3600.0
    assert ip_detail._build_live_features(live_ip) is None


def test_flow_without_any_verdict_returns_none(live_ip):
    tracker.invalidate_cache(live_ip)
    assert ip_detail._build_live_features(live_ip) is None
