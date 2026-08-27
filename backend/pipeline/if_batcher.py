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
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _thread = threading.Thread(target=_loop, name="if-batcher", daemon=True)
        _thread.start()


def infer(vec_scaled) -> Future:
    fut = Future()
    with _cond:
        _tray.append((vec_scaled, fut))
        _cond.notify()
    return fut


def _loop() -> None:
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
    with _cond:
        return {
            "tray_len": len(_tray),
            "batches": _batches,
            "items": _items,
        }


def reset_for_tests() -> None:
    with _cond:
        _tray.clear()
