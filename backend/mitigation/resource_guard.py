import time
import threading
import logging

log = logging.getLogger(__name__)

# ── Thresholds (%) ─────────────────────────────────────────────────────────
CPU_WARN  = 70.0
CPU_HIGH  = 85.0
CPU_CRIT  = 95.0

MEM_WARN  = 75.0
MEM_HIGH  = 85.0
MEM_CRIT  = 95.0

# Poll interval in seconds
GUARD_POLL_INTERVAL = 5.0

# Consecutive HIGH readings before triggering action (avoids reacting to spikes)
HIGH_CONSECUTIVE_THRESHOLD = 3


class ResourceGuard:
    # Monitors host CPU and memory.
    # Levels:
    #   WARN  (CPU>=70 or MEM>=75): log only
    #   HIGH  (CPU>=85 or MEM>=85): clear non-permanent entries after 3 consecutive reads
    #   CRIT  (CPU>=95 or MEM>=95): emergency clear all entries + sinkhole, pause detections

    def __init__(self):
        self._running          = False
        self._thread           = None
        self._state_machine    = None
        self._deception        = None
        self._consecutive_high = 0
        self._paused           = False

    def set_state_machine(self, sm) -> None:
        self._state_machine = sm

    def set_deception(self, dec) -> None:
        self._deception = dec

    @property
    def is_paused(self) -> bool:
        # True during CRIT — decision_engine checks this before new detections
        return self._paused

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, name="resource-guard", daemon=True)
        self._thread.start()
        log.info("ResourceGuard started — poll=%.0fs  CPU warn/high/crit=%.0f/%.0f/%.0f%%"
                 "  MEM warn/high/crit=%.0f/%.0f/%.0f%%",
                 GUARD_POLL_INTERVAL, CPU_WARN, CPU_HIGH, CPU_CRIT,
                 MEM_WARN, MEM_HIGH, MEM_CRIT)

    def stop(self) -> None:
        self._running = False

    # ── Internal ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            try:
                self._check()
            except Exception as exc:
                log.warning("ResourceGuard error: %s", exc)
            time.sleep(GUARD_POLL_INTERVAL)

    def _check(self) -> None:
        cpu_pct, mem_pct = self._sample()
        level = self._classify(cpu_pct, mem_pct)

        if level == "CRIT":
            self._consecutive_high += 1
            if not self._paused:
                log.critical("ResourceGuard CRIT: CPU=%.1f%%  MEM=%.1f%% — "
                             "pausing detections, emergency clear", cpu_pct, mem_pct)
                self._paused = True
                self._emergency_clear_all()

        elif level == "HIGH":
            self._consecutive_high += 1
            self._paused = False
            if self._consecutive_high >= HIGH_CONSECUTIVE_THRESHOLD:
                log.warning("ResourceGuard HIGH (%dx): CPU=%.1f%%  MEM=%.1f%% — "
                            "clearing non-permanent entries",
                            self._consecutive_high, cpu_pct, mem_pct)
                self._clear_non_permanent()

        elif level == "WARN":
            self._consecutive_high = 0
            self._paused = False
            log.warning("ResourceGuard WARN: CPU=%.1f%%  MEM=%.1f%%", cpu_pct, mem_pct)

        else:
            # NORMAL — reset counters
            if self._consecutive_high > 0 or self._paused:
                log.info("ResourceGuard NORMAL: CPU=%.1f%%  MEM=%.1f%% — resuming",
                         cpu_pct, mem_pct)
            self._consecutive_high = 0
            self._paused = False

    def _classify(self, cpu: float, mem: float) -> str:
        if cpu >= CPU_CRIT or mem >= MEM_CRIT:
            return "CRIT"
        if cpu >= CPU_HIGH or mem >= MEM_HIGH:
            return "HIGH"
        if cpu >= CPU_WARN or mem >= MEM_WARN:
            return "WARN"
        return "NORMAL"

    def _sample(self) -> tuple[float, float]:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=1.0)
            mem = psutil.virtual_memory().percent
            return cpu, mem
        except ImportError:
            log.warning("ResourceGuard: psutil not installed")
            return 0.0, 0.0
        except Exception as exc:
            log.warning("ResourceGuard: sample error — %s", exc)
            return 0.0, 0.0

    def _clear_non_permanent(self) -> None:
        if self._state_machine:
            cleared = self._state_machine.clear_all_non_permanent()
            log.info("ResourceGuard: cleared %d non-permanent entries", cleared)

    def _emergency_clear_all(self) -> None:
        # Clears non-permanent state_machine entries AND all sinkhole entries.
        # Uses public methods only — no access to private internals.
        self._clear_non_permanent()
        if self._deception:
            cleared = self._deception.emergency_clear()
            if cleared:
                log.info("ResourceGuard: emergency cleared %d sinkhole entries", cleared)


# Module-level singleton
resource_guard = ResourceGuard()