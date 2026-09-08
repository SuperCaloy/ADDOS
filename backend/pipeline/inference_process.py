"""Dedicated subprocess for IF + RF inference.

Bypasses the GIL by running ML models in a separate process.
Workers enqueue flow features; the subprocess batches and returns results.
"""
import multiprocessing
import threading
import time
import logging
import os

log = logging.getLogger(__name__)

# Sentinel to shut down the subprocess (must be picklable across processes)
_SHUTDOWN = "__INFERENCE_SHUTDOWN__"


def _inference_worker(input_queue: multiprocessing.Queue,
                      output_queue: multiprocessing.Queue,
                      ready_event: multiprocessing.Event) -> None:
    """Subprocess entry point: load models, then loop processing batches."""
    import warnings
    warnings.filterwarnings("ignore", message=".*n_jobs.*")
    try:
        from backend.models import if_pipeline, rf_pipeline, loader
        loader.load_all()
        log.info("Inference subprocess: models loaded")
        ready_event.set()
    except Exception:
        log.exception("Inference subprocess: failed to load models")
        return

    tray = []
    last_flush = time.monotonic()
    FLUSH_INTERVAL_S = 0.025  # 25ms internal batch window

    while True:
        try:
            item = input_queue.get(timeout=0.05)
            if item == _SHUTDOWN:
                break
            tray.append(item)
        except Exception:
            pass

        now = time.monotonic()
        should_flush = (
            len(tray) >= 16
            or (now - last_flush) >= FLUSH_INTERVAL_S
            or (len(tray) > 0 and input_queue.empty())
        )

        if not should_flush:
            continue

        if not tray:
            last_flush = now
            continue

        batch = tray
        tray = []
        last_flush = now

        results = []
        for src_ip, if_vec, rf_vec, meta in batch:
            try:
                if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)
                attack_class = "Uncertain"
                confidence = 0.0
                if is_anomaly and rf_vec is not None:
                    attack_class, confidence = rf_pipeline.run_rf_inference(rf_vec)
                results.append((src_ip, if_score, is_anomaly, attack_class, confidence, meta, None))
            except Exception as e:
                results.append((src_ip, 0.0, False, "Uncertain", 0.0, meta, str(e)))

        for result in results:
            try:
                output_queue.put_nowait(result)
            except Exception:
                log.warning("Inference output queue full, dropping result for %s", result[0])


class InferenceProcess:
    """Manages a dedicated inference subprocess."""

    def __init__(self):
        self._input_queue = multiprocessing.Queue(maxsize=500)
        self._output_queue = multiprocessing.Queue(maxsize=500)
        self._ready = multiprocessing.Event()
        self._proc = None
        self._results = {}  # src_ip -> result (for non-blocking poll)
        self._lock = threading.Lock()

    def start(self) -> None:
        self._proc = multiprocessing.Process(
            target=_inference_worker,
            args=(self._input_queue, self._output_queue, self._ready),
            daemon=True,
        )
        self._proc.start()
        if not self._ready.wait(timeout=10.0):
            log.error("Inference subprocess failed to become ready")
        else:
            log.info("Inference subprocess started (pid=%s)", self._proc.pid)

    def stop(self) -> None:
        if self._proc and self._proc.is_alive():
            try:
                self._input_queue.put_nowait(_SHUTDOWN)
            except Exception:
                pass
            self._proc.join(timeout=3.0)
            if self._proc.is_alive():
                self._proc.kill()
                self._proc.join(timeout=2.0)
            # Close queues to unblock internal feeder threads
            for q in (self._input_queue, self._output_queue):
                try:
                    q.close()
                    q.join_thread()
                except Exception:
                    pass

    def submit(self, src_ip: str, if_vec, rf_vec=None, meta: dict = None) -> None:
        """Non-blocking submit. Returns immediately."""
        try:
            self._input_queue.put_nowait((src_ip, if_vec, rf_vec, meta or {}))
        except Exception:
            log.debug("Inference input queue full, dropping %s", src_ip)

    def poll_results(self) -> list:
        """Drain all available results from the output queue. Non-blocking."""
        results = []
        while True:
            try:
                result = self._output_queue.get_nowait()
                results.append(result)
            except Exception:
                break
        return results

    def is_ready(self) -> bool:
        return self._ready.is_set()


# Module-level singleton
inference_process = InferenceProcess()
