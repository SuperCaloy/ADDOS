import time
import threading
import logging

log = logging.getLogger(__name__)

# ── Thresholds (%) ─────────────────────────────────────────────────────────
CPU_WARN  = 85.0   # log warning only
CPU_HIGH  = 95.0   # throttle packet-in evaluation rate
CPU_CRIT  = 99.0   # install OVS rate-limit rule to shed excess packet-in

MEM_WARN  = 70.0   # log warning only
MEM_HIGH  = 85.0   # log + monitor closely
MEM_CRIT  = 95.0   # log critical — memory ceiling reached

# Poll interval in seconds
GUARD_POLL_INTERVAL = 2.0

# Consecutive HIGH readings before throttling (avoids reacting to brief spikes)
HIGH_CONSECUTIVE_THRESHOLD = 2


class ResourceGuard:
    def __init__(self):
        self._running          = False
        self._thread           = None
        self._consecutive_high = 0
        self._crit_rules_active = False
        self._throttle_delay    = 0.0   # injected into detection poll when HIGH
        self._attack_proto      = None  # nw_proto number of current attack (1=ICMP, 6=TCP, 17=UDP)

    @property
    def throttle_delay(self) -> float:
        # Read by decision_engine between flow evaluations when HIGH.
        return self._throttle_delay

    @property
    def is_paused(self) -> bool:
        # Always False — ML is never paused under this design.
        return False

    def set_attack_proto(self, attack_class: str) -> None:
        # Map ML attack class → IP protocol number.
        # Called by decision_engine on every confirmed anomaly.
        # Used by _install_rate_limit_rules to drop only the attacking protocol.
        _proto_map = {
            "ICMP Flood": 1,   # ICMP
            "SYN Flood":  6,   # TCP
            "UDP Flood":  17,  # UDP
        }
        proto = _proto_map.get(attack_class)
        if proto is not None:
            self._attack_proto = proto

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, name="resource-guard", daemon=True
        )
        self._thread.start()
        log.info(
            "ResourceGuard started — poll=%.0fs  "
            "CPU warn/high/crit=%.0f/%.0f/%.0f%%  "
            "MEM warn/high/crit=%.0f/%.0f/%.0f%%",
            GUARD_POLL_INTERVAL,
            CPU_WARN, CPU_HIGH, CPU_CRIT,
            MEM_WARN, MEM_HIGH, MEM_CRIT,
        )

    def stop(self) -> None:
        self._running = False

    # ── Internal ───────────────────────────────────────────────────────────

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
            # Tier 3 — install OVS packet-in rate-limit rules.
            # Sheds excess packet-in load at data plane before it reaches Ryu.
            # ML detections and quarantine entries are untouched.
            self._consecutive_high += 1
            self._throttle_delay = 0.05   # 50ms between detections
            if not self._crit_rules_active:
                log.critical(
                    "ResourceGuard CRIT: CPU=%.1f%% MEM=%.1f%% — "
                    "installing OVS packet-in rate-limit rules",
                    cpu_pct, mem_pct,
                )
                self._install_rate_limit_rules()
                self._crit_rules_active = True

        elif level == "HIGH":
            # Tier 2 — throttle detection poll rate only.
            # Slows how fast new flows enter the ML pipeline.
            # Does NOT touch quarantine or ML state.
            self._consecutive_high += 1
            if self._consecutive_high >= HIGH_CONSECUTIVE_THRESHOLD:
                self._throttle_delay = 0.02   # 20ms between detections
                log.warning(
                    "ResourceGuard HIGH (%dx): CPU=%.1f%% MEM=%.1f%% — "
                    "throttling detection rate (delay=%.0fms)",
                    self._consecutive_high, cpu_pct, mem_pct,
                    self._throttle_delay * 1000,
                )
            # Remove CRIT rules if CPU dropped back to HIGH range
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False

        elif level == "WARN":
            # Tier 1 — log only, no interference.
            self._consecutive_high = 0
            self._throttle_delay   = 0.0
            log.warning(
                "ResourceGuard WARN: CPU=%.1f%% MEM=%.1f%%",
                cpu_pct, mem_pct,
            )
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False

        else:
            # NORMAL — reset everything
            if self._consecutive_high > 0 or self._throttle_delay > 0:
                log.info(
                    "ResourceGuard NORMAL: CPU=%.1f%% MEM=%.1f%% — "
                    "all throttles removed",
                    cpu_pct, mem_pct,
                )
            self._consecutive_high  = 0
            self._throttle_delay    = 0.0
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False

    def _classify(self, cpu: float, mem: float) -> str:
        if cpu >= CPU_CRIT  or mem >= MEM_CRIT:  return "CRIT"
        if cpu >= CPU_HIGH  or mem >= MEM_HIGH:  return "HIGH"
        if cpu >= CPU_WARN  or mem >= MEM_WARN:  return "WARN"
        return "NORMAL"

    def _sample(self) -> tuple[float, float]:
        # Use controller (Ryu) CPU and memory via monitor._get_ctrl_metrics().
        # Avoids duplicating psutil logic and stays consistent with dashboard.
        try:
            from backend.mitigation.monitor import _get_ctrl_metrics
            ctrl_cpu, ctrl_mem_mb = _get_ctrl_metrics()
            # Convert memory MB to % of 500MB practical Ryu ceiling
            # Use 150MB ceiling — matches RLIMIT_AS set in ryu_controller.py
            ctrl_mem_pct = min((ctrl_mem_mb / 150.0) * 100.0, 100.0)
            return ctrl_cpu, ctrl_mem_pct
        except Exception as exc:
            log.warning("ResourceGuard: sample error — %s", exc)
            return 0.0, 0.0

    def _install_rate_limit_rules(self) -> None:
        # Send proto_block command to Ryu via ZMQ.
        # Ryu installs an OpenFlow drop rule for the attacking protocol on all switches.
        # Priority 50 — above table-miss (1), below per-IP block rules (80+).
        # Catches rand-source floods that bypass per-IP block rules.
        if self._attack_proto is None:
            log.warning("ResourceGuard: no attack proto known — skipping proto drop")
            return

        proto = self._attack_proto
        try:
            from backend.mitigation.zmq_commander import commander
            commander.send({"action": "proto_block", "proto": proto, "remove": False})
            log.info("ResourceGuard: proto_block sent to Ryu — nw_proto=%d", proto)
        except Exception as exc:
            log.warning("ResourceGuard: failed to send proto_block: %s", exc)

    def _remove_rate_limit_rules(self) -> None:
        # Send proto_block remove command to Ryu via ZMQ.
        # Ryu removes the protocol drop rule from all switches.
        if self._attack_proto is None:
            return

        proto = self._attack_proto
        try:
            from backend.mitigation.zmq_commander import commander
            commander.send({"action": "proto_block", "proto": proto, "remove": True})
            log.info("ResourceGuard: proto_block removed from Ryu — nw_proto=%d", proto)
        except Exception as exc:
            log.warning("ResourceGuard: failed to send proto_block remove: %s", exc)

    # ── Kept for backward compatibility — no longer used internally ────────

    def set_state_machine(self, sm) -> None:
        # Kept for compatibility with main.py — no longer used.
        pass

    def set_deception(self, dec) -> None:
        # Kept for compatibility with main.py — no longer used.
        pass


# Module-level singleton
resource_guard = ResourceGuard()