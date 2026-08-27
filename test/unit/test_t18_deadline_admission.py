"""T18: deadline-based admission with service-time EMA + phase exemption.

Implements the verified strategy (plan measurement-2026-08-27 sec 12, lever 1):
- S7: true per-origin EMA of full-inference service time (drain math input).
- S5: IPs in mitigation phase >= 2 are exempt from admission shedding so
  probation/ban-expiry keep receiving live evidence (RT-J).
- R3b: deadline admission behind DEADLINE_ADMISSION_ENABLED (default OFF):
  refuse a priority-1 item when estimated queue drain time exceeds
  WORKER_ITEM_TIMEOUT_S minus a margin. Replaces the static depth check
  while enabled.
"""
import time
from types import SimpleNamespace

import pytest

from backend.pipeline import worker
from backend.mitigation.state_machine import state_machine


@pytest.fixture()
def deep_queue(monkeypatch):
    monkeypatch.setattr(worker._queue, "qsize", lambda: 900)
    puts = []
    monkeypatch.setattr(worker._queue, "put_nowait",
                        lambda item: puts.append(item))
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any",
                        lambda ip: False)
    # Defensive: no phase state leaks between tests (default-deny baseline)
    state_machine._states.clear()
    yield puts
    state_machine._states.clear()


@pytest.fixture()
def clean_ema():
    worker._svc_ema["full"] = None
    yield
    worker._svc_ema["full"] = None


def submit(ip="10.0.0.5"):
    worker.submit(ip, {"packet_count": 10}, {})


# --- S5: phase >= 2 exemption (active whenever admission control is on) ---

def test_phase2_unflagged_ip_bypasses_static_admission(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    state_machine._states["10.0.0.5"] = SimpleNamespace(phase=2)

    submit()

    assert len(deep_queue) == 1


def test_phase2_unflagged_ip_bypasses_deadline_admission(
        deep_queue, monkeypatch, clean_ema):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", True)
    worker._svc_ema["full"] = 1000.0
    state_machine._states["10.0.0.5"] = SimpleNamespace(phase=2)

    submit()

    assert len(deep_queue) == 1


def test_unknown_ip_default_deny_static(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)

    submit()

    assert deep_queue == []


def test_phase1_ip_not_exempt(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    state_machine._states["10.0.0.5"] = SimpleNamespace(phase=1)

    submit()

    assert deep_queue == []


# --- S7: service-time EMA ---

def test_svc_ema_seeds_first_sample_then_blends(clean_ema):
    worker._record_svc_ema(100.0)
    assert worker.get_svc_ema_ms() == pytest.approx(100.0)

    worker._record_svc_ema(200.0)
    expected = worker.SVC_EMA_ALPHA * 200.0 + (1 - worker.SVC_EMA_ALPHA) * 100.0
    assert worker.get_svc_ema_ms() == pytest.approx(expected)


def test_svc_ema_fallback_when_no_samples(clean_ema):
    assert worker.get_svc_ema_ms() == pytest.approx(worker.SVC_EMA_FALLBACK_MS)


# --- R3b: deadline admission (default OFF) ---

def test_deadline_off_keeps_static_behavior(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", False)
    before = worker.get_admission_counters()

    submit()

    assert deep_queue == []
    after = worker.get_admission_counters()
    assert after["admission_dropped"] == before["admission_dropped"] + 1
    assert after["admission_deadline_dropped"] == \
        before["admission_deadline_dropped"]


def test_deadline_refuses_when_drain_exceeds_budget(
        deep_queue, monkeypatch, clean_ema):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", True)
    # drain = 900 items * 1.0 s / 8 workers = 112.5 s >> 2.5 s budget
    worker._svc_ema["full"] = 1000.0
    before = worker.get_admission_counters()["admission_deadline_dropped"]

    submit()

    assert deep_queue == []
    assert worker.get_admission_counters()["admission_deadline_dropped"] == \
        before + 1


def test_deadline_admits_when_drain_within_budget(
        deep_queue, monkeypatch, clean_ema):
    monkeypatch.setattr(worker._queue, "qsize", lambda: 1)
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", True)
    # drain = 1 * 1.0 / 8 = 0.125 s < 2.5 s budget
    worker._svc_ema["full"] = 1000.0

    submit()

    assert len(deep_queue) == 1


def test_deadline_flagged_ip_always_admitted(
        deep_queue, monkeypatch, clean_ema):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", True)
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any",
                        lambda ip: True)
    worker._svc_ema["full"] = 1000.0

    submit()

    assert len(deep_queue) == 1
    assert deep_queue[0][0] == 0  # priority 0
