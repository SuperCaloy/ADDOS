import threading
import time
import logging
import psutil
from backend.database import writer

log = logging.getLogger(__name__)

_pps_counter = 0
_pps_lock    = threading.Lock()


def record_packet() -> None:
    """Call this per processed flow to track pps."""
    global _pps_counter
    with _pps_lock:
        _pps_counter += 1


def start() -> None:
    def _loop():
        global _pps_counter
        proc = psutil.Process()
        while True:
            time.sleep(5)
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = proc.memory_info().rss / (1024 * 1024)  # MB
                with _pps_lock:
                    pps = _pps_counter / 5.0
                    _pps_counter = 0
                writer.log_system_metrics(cpu, mem, pps)
            except Exception:
                log.exception("monitor: failed to log metrics")

    t = threading.Thread(target=_loop, name="sys-monitor", daemon=True)
    t.start()
    log.info("System monitor started")