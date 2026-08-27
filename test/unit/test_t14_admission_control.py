"""T14: admission control at submit.

When ADMISSION_CONTROL_ENABLED and the queue is deeper than
WORKER_ADMISSION_DEPTH, UNFLAGGED priority-1 submissions are dropped at
submit (counter admission_dropped) instead of aging 3s in the queue and
dying at triage after burning parse+enqueue+dequeue work. Flagged IPs
(priority 0) are ALWAYS admitted: they are the active-response path.
Default flag OFF preserves current behavior exactly.
"""
import pytest

from backend.pipeline import worker


@pytest.fixture()
def deep_queue(monkeypatch):
    monkeypatch.setattr(worker._queue, "qsize", lambda: 900)
    puts = []
    monkeypatch.setattr(worker._queue, "put_nowait",
                        lambda item: puts.append(item))
    return puts


def test_default_flag_off_preserves_current_behavior(deep_queue, monkeypatch):
    # Pins the admission-disabled state regardless of backend/config.py,
    # which the operator flips for live runs.
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", False)
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    before = worker.get_admission_counters()["admission_dropped"]
    worker.submit("10.0.0.5", {"packet_count": 10}, {})
    assert len(deep_queue) == 1
    assert worker.get_admission_counters()["admission_dropped"] == before


def test_deep_queue_sheds_unflagged(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    # Static-depth path: pin the deadline gate OFF so the counter under
    # test is admission_dropped regardless of backend/config.py.
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", False)
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: False)
    before = worker.get_admission_counters()["admission_dropped"]
    worker.submit("10.0.0.5", {"packet_count": 10}, {})
    assert deep_queue == []
    assert worker.get_admission_counters()["admission_dropped"] == before + 1


def test_deep_queue_still_admits_flagged(deep_queue, monkeypatch):
    monkeypatch.setattr(worker, "ADMISSION_CONTROL_ENABLED", True)
    monkeypatch.setattr(worker, "DEADLINE_ADMISSION_ENABLED", False)
    monkeypatch.setattr(worker.flood_filter, "is_flagged_any", lambda ip: True)
    worker.submit("10.0.0.5", {"packet_count": 10}, {})
    assert len(deep_queue) == 1
    assert deep_queue[0][0] == 0  # priority 0 jumps the queue
