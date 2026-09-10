# Dynamic micro-batcher for Isolation Forest anomaly score inference.
# Groups incoming feature vectors across a sliding time window to saturate vectorized batch scoring.

import threading
import time
from concurrent.futures import Future

from backend.config import IF_BATCH_MAX, IF_BATCH_WINDOW_MS
from backend.models import if_pipeline

_lock = threading.Lock()
_cond = threading.Condition(_lock)
_tray: list = []
_thread: threading.Thread | None = None
_batches = 0
_items = 0


def ensure_started() -> None:
    # Ensures the background batch processing thread is active and ready to consume vectors.
    # Lazily initializes the daemon thread under thread-safe locking.
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _thread = threading.Thread(target=_loop, name="if-batcher", daemon=True)
        _thread.start()


def infer(vec_scaled) -> Future:
    # Submits a scaled feature vector to the batching queue and returns a Future.
    # Wakes the background worker loop to process when batch size or time window expires.
    fut = Future()
    with _cond:
        _tray.append((vec_scaled, fut))
        _cond.notify()
    return fut


def _loop() -> None:
    # Background worker loop waiting for batch window timeout or capacity thresholds.
    # Invokes vectorized inference and completes waiting futures with score results.
    global _batches, _items
    window_s = IF_BATCH_WINDOW_MS / 1000.0
    while True:
        with _cond:
            while not _tray:
                _cond.wait()
            deadline = time.monotonic() + window_s
            while len(_tray) < IF_BATCH_MAX:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                _cond.wait(remaining)
            batch = _tray[:IF_BATCH_MAX]
            del _tray[:len(batch)]
            _batches += 1
            _items += len(batch)

        try:
            results = if_pipeline.run_if_inference_batch([v for v, _ in batch])
            if len(results) != len(batch):
                raise RuntimeError(
                    f"batch result count mismatch: {len(results)} != {len(batch)}")
            for (_, fut), res in zip(batch, results):
                fut.set_result(res)
        except Exception as exc:
            for _, fut in batch:
                fut.set_exception(exc)


def stats() -> dict:
    # Returns operational metrics for active tray length, total batches, and processed items.
    # Used by observability inspectors and test suites.
    with _cond:
        return {
            "tray_len": len(_tray),
            "batches": _batches,
            "items": _items,
        }


def reset_for_tests() -> None:
    # Clears pending feature vectors in the tray.
    # Used to reset batching state between test fixture executions.
    with _cond:
        _tray.clear()
