import threading
import time
import logging
import psutil
from backend.database import writer

log = logging.getLogger(__name__)

_pps_counter = 0
_pps_lock    = threading.Lock()


def _get_ctrl_metrics() -> tuple:
    """Find ryu-manager process + all children, return (cpu%, mem_mb).
    Includes child processes (eventlet workers, ZMQ threads spawned by Ryu).
    Returns (0,0) if not found."""
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if 'ryu-manager' in (proc.info['name'] or '') or \
               any('ryu-manager' in c for c in (proc.info['cmdline'] or [])):

                # --- Collect ryu-manager + all its children ---
                all_procs = [proc] + proc.children(recursive=True)

                # --- Sum CPU across all, normalize to system-relative % ---
                total_cpu = sum(
                    p.cpu_percent(interval=None)
                    for p in all_procs
                    if p.is_running()
                ) / psutil.cpu_count()

                # --- Sum RSS memory across all processes ---
                total_mem = sum(
                    p.memory_info().rss
                    for p in all_procs
                    if p.is_running()
                ) / (1024 * 1024)

                return (total_cpu, total_mem)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return (0.0, 0.0)


def record_packet() -> None:
    global _pps_counter
    with _pps_lock:
        _pps_counter += 1


def start() -> None:
    def _loop():
        global _pps_counter
        proc = psutil.Process()

        # --- Prime cpu_percent — first call always returns 0.0 ---
        psutil.cpu_percent(interval=None)
        _get_ctrl_metrics()

        while True:
            time.sleep(1)
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = proc.memory_info().rss / (1024 * 1024)
                ctrl_cpu, ctrl_mem = _get_ctrl_metrics()
                with _pps_lock:
                    pps = _pps_counter / 1.0
                    _pps_counter = 0

                # --- Tag as attack or baseline using live ground truth ---
                try:
                    from backend.api.stats import get_active_attacks
                    is_attack = len(get_active_attacks()) > 0
                except Exception:
                    is_attack = False

                writer.log_system_metrics(cpu, mem, pps, is_attack=is_attack,
                                          ctrl_cpu=ctrl_cpu, ctrl_mem=ctrl_mem)
            except Exception:
                log.exception("monitor: failed to log metrics")

    t = threading.Thread(target=_loop, name="sys-monitor", daemon=True)
    t.start()
    log.info("System monitor started")