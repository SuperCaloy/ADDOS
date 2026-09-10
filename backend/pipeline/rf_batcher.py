# Adaptive micro-batcher for Random Forest multiclass attack classification.
# Dynamically tunes batch collection windows based on pipeline worker queue pressure.

import threading
import time
from concurrent.futures import Future

from backend.config import RF_BATCH_MAX
from backend.models import rf_pipeline

_lock = threading.Lock()
_cond = threading.Condition(_lock)
_tray: list = []
_thread: threading.Thread | None = None
_stats = {"batches": 0, "items": 0}

_CALM_WINDOW_MS = 5
_BALANCED_WINDOW_MS = 10
_WAVE_WINDOW_MS = 20


def _adaptive_window_ms() -> int:
    # Determines adaptive batch window size based on worker queue depth.
    # Yields shorter latency under low load and higher batch throughput under heavy load.
    from backend.pipeline import worker
    depth = worker.get_queue_depth()
    if depth < 10:
        return _CALM_WINDOW_MS
    if depth < 50:
        return _BALANCED_WINDOW_MS
    return _WAVE_WINDOW_MS


def ensure_started() -> None:
    # Ensures the background batch thread is running and ready for inference jobs.
    # Idempotent thread startup guarded by internal re-entrant lock.
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _thread = threading.Thread(target=_loop, name="rf-batcher", daemon=True)
        _thread.start()


def infer(vec_scaled) -> Future:
    # Adds a scaled feature vector to the batch tray and returns a Future.
    # Wakes waiting inference thread to evaluate batch when ready.
    fut = Future()
    with _cond:
        _tray.append((vec_scaled, fut))
        _cond.notify()
    return fut


def _loop() -> None:
    # Background execution loop assembling batches within the adaptive time window.
    # Runs batched Random Forest inference and fulfills client futures with classifications.
    while True:
        window_s = _adaptive_window_ms() / 1000.0
        with _cond:
            while not _tray:
                _cond.wait()
            deadline = time.monotonic() + window_s
            while len(_tray) < RF_BATCH_MAX:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                _cond.wait(remaining)
            batch = _tray[:RF_BATCH_MAX]
            del _tray[:len(batch)]
            _stats["batches"] += 1
            _stats["items"] += len(batch)

        try:
            results = rf_pipeline.run_rf_inference_batch([v for v, _ in batch])
            if len(results) != len(batch):
                raise RuntimeError(
                    f"batch result count mismatch: {len(results)} != {len(batch)}")
            for (_, fut), res in zip(batch, results):
                fut.set_result(res)
        except Exception as exc:
            for _, fut in batch:
                fut.set_exception(exc)


def reset_for_tests() -> None:
    # Empties the current batch tray.
    # Resets batcher state during unit test setup.
    with _cond:
        _tray.clear()


def stats() -> dict:
    # Returns statistics on queue length, total executed batches, and item throughput.
    # Thread-safe snapshot under condition lock.
    with _cond:
        return {
            "tray_len": len(_tray),
            "batches": _stats["batches"],
            "items": _stats["items"],
        }
