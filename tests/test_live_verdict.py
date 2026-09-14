"""RED tests: tracker last-verdict store for degrading live endpoint.

Plan: notes/tasks/live-drawer-reliability-plan.md Phase 1.
Run: python3 -m pytest tests/test_live_verdict.py -v
"""
import time

from backend.pipeline.flow_tracker import FlowTracker


def test_remember_then_read_returns_verdict():
    tracker = FlowTracker()
    tracker.update_flow('10.0.0.9', {'packet_count': 100})
    tracker.remember_verdict('10.0.0.9', 0.64, True, 'SYN Flood', 0.9)
    verdict = tracker.last_verdict('10.0.0.9')
    assert verdict['if_score'] == 0.64
    assert verdict['is_anomaly'] is True
    assert verdict['attack_class'] == 'SYN Flood'
    assert verdict['confidence'] == 0.9
    assert verdict['age_s'] >= 0.0


def test_normal_verdicts_are_stored():
    tracker = FlowTracker()
    tracker.update_flow('10.0.0.9', {'packet_count': 10})
    tracker.remember_verdict('10.0.0.9', 0.2, False, 'Normal', 0.0)
    verdict = tracker.last_verdict('10.0.0.9')
    assert verdict['is_anomaly'] is False


def test_unknown_ip_returns_none():
    tracker = FlowTracker()
    assert tracker.last_verdict('10.9.9.9') is None


def test_flow_removal_clears_verdict():
    tracker = FlowTracker()
    tracker.update_flow('10.0.0.9', {'packet_count': 100})
    tracker.remember_verdict('10.0.0.9', 0.64, True, 'SYN Flood', 0.9)
    tracker.remove_flow('10.0.0.9')
    assert tracker.last_verdict('10.0.0.9') is None


def test_latest_verdict_wins():
    tracker = FlowTracker()
    tracker.update_flow('10.0.0.9', {'packet_count': 100})
    tracker.remember_verdict('10.0.0.9', 0.5, False, 'Normal', 0.0)
    tracker.remember_verdict('10.0.0.9', 0.7, True, 'UDP Flood', 0.8)
    assert tracker.last_verdict('10.0.0.9')['attack_class'] == 'UDP Flood'


def test_age_grows_with_time():
    tracker = FlowTracker()
    tracker.update_flow('10.0.0.9', {'packet_count': 100})
    tracker.remember_verdict('10.0.0.9', 0.64, True, 'SYN Flood', 0.9)
    time.sleep(0.05)
    assert tracker.last_verdict('10.0.0.9')['age_s'] >= 0.05
