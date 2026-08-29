import threading
import time
import logging
import psutil
from backend.database import writer
from backend.config import ML_ENABLED

log = logging.getLogger(__name__)

_pps_counter = 0
_pps_lock    = threading.Lock()


# Cached ryu process list, avoids re-discovering on every call.
# cpu_percent(interval=None) needs the same object called twice with time between, so reuse the same psutil.Process instances.
_ctrl_procs: list = []
_ctrl_procs_lock = threading.Lock()


def _get_ctrl_metrics() -> tuple:
    """Find ryu-manager process + all children, return (cpu%, mem_mb).
    Reuses cached process objects so cpu_percent(interval=None) is accurate.
    Returns (0,0) if not found."""
    global _ctrl_procs

    with _ctrl_procs_lock:
        # Refresh proc list if empty or any proc died
        if not _ctrl_procs or not any(p.is_running() for p in _ctrl_procs):
            _ctrl_procs = []
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    if 'ryu-manager' in (proc.info['name'] or '') or \
                       any('ryu-manager' in c for c in (proc.info['cmdline'] or [])):
                        _ctrl_procs = [proc] + proc.children(recursive=True)
                        # Prime cpu_percent on first discovery -- first call returns 0.0
                        for p in _ctrl_procs:
                            try:
                                p.cpu_percent(interval=None)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        if not _ctrl_procs:
            return (0.0, 0.0)

        try:
            # interval=None uses time elapsed since last call -- accurate when
            # called on the same cached objects every ~1s from the monitor loop.
            total_cpu = min(sum(
                p.cpu_percent(interval=None)
                for p in _ctrl_procs
                if p.is_running()
            ), 100.0)

            total_mem = sum(
                p.memory_info().rss
                for p in _ctrl_procs
                if p.is_running()
            ) / (1024 * 1024)

            return (total_cpu, total_mem)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            _ctrl_procs = []
            return (0.0, 0.0)


def record_packet() -> None:
    global _pps_counter
    with _pps_lock:
        _pps_counter += 1


def start() -> None:
    def _loop():
        global _pps_counter
        proc = psutil.Process()

        # --- Prime cpu_percent: first call always returns 0.0 ---
        psutil.cpu_percent(interval=None)
        proc.cpu_percent(interval=None)
        _get_ctrl_metrics()

        while True:
            # Poll hping3 across the full 1s window (CPU is averaged over the past 1s).
            # Polling 5x avoids missing attack traffic that stopped before a single check.
            attack_seen_in_window = False
            for _ in range(5):
                time.sleep(0.2)
                try:
                    if any(
                        'hping3' in ' '.join(p.info.get('cmdline') or [])
                        or p.info.get('name') == 'hping3'
                        for p in psutil.process_iter(['name', 'cmdline'])
                    ):
                        attack_seen_in_window = True
                except Exception:
                    pass

            try:
                cpu = psutil.cpu_percent(interval=None)
                proc_cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_info().rss / (1024 * 1024)
                ctrl_cpu, ctrl_mem = _get_ctrl_metrics()
                with _pps_lock:
                    pps = _pps_counter / 1.0
                    _pps_counter = 0

                # --- Tag as attack or baseline using live ground truth ---
                try:
                    hping3_running = attack_seen_in_window

                    if ML_ENABLED:
                        from backend.api.stats import get_active_attacks
                        from backend.mitigation.state_machine import state_machine
                        _active_gt = get_active_attacks()
                        # Topology-reported ground truth is the primary signal; hping3 scan is a fallback for gaps.
                        is_attack = len(_active_gt) > 0 or hping3_running
                        # Mitigating means the state machine has active IPs under quarantine/ban; distinct from is_attack (traffic present).
                        is_mitigating = len(state_machine.get_active_list()) > 0
                    else:
                        # ML OFF: no mitigation runs so is_mitigating stays False, but topology ground truth is still used for attack labeling.
                        from backend.api.stats import get_active_attacks
                        _active_gt = get_active_attacks()
                        is_attack = len(_active_gt) > 0 or hping3_running
                        is_mitigating = False
                except Exception:
                    is_attack = False
                    is_mitigating = False

                writer.log_system_metrics(cpu, mem, pps, is_attack=is_attack,
                                          ctrl_cpu=ctrl_cpu, ctrl_mem=ctrl_mem,
                                          is_mitigating=is_mitigating,
                                          proc_cpu_percent=proc_cpu)
            except Exception:
                log.exception("monitor: failed to log metrics")

    t = threading.Thread(target=_loop, name="sys-monitor", daemon=True)
    t.start()
    log.info("System monitor started")