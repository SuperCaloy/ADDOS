import time
import threading
import logging
from backend.config import ML_ENABLED

log = logging.getLogger(__name__)

# Thresholds (%)
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
        self._running           = False
        self._thread            = None
        self._consecutive_high  = 0
        self._crit_rules_active = False
        self._throttle_delay    = 0.0
        self._attack_proto      = None  # nw_proto of current attack (1=ICMP, 6=TCP, 17=UDP)
        self._installed_proto   = None  # nw_proto actually installed via OVS rule
        self._tier              = "NORMAL"

    @property
    def throttle_delay(self) -> float:
        # Read by decision_engine between flow evaluations when HIGH.
        return self._throttle_delay

    @property
    def is_paused(self) -> bool:
        # Always False — ML is never paused under this design.
        return False

    @property
    def tier(self) -> str:
        return self._tier

    def set_attack_proto(self, attack_class: str) -> None:
        # Map ML attack class to IP protocol number.
        # Called by decision_engine on every confirmed anomaly.
        _proto_map = {
            "ICMP Flood": 1,
            "SYN Flood":  6,
            "UDP Flood":  17,
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

    # Internal

    def _loop(self) -> None:
        while self._running:
            try:
                self._check()
            except Exception as exc:
                log.warning("ResourceGuard error: %s", exc)
            time.sleep(GUARD_POLL_INTERVAL)

    def _check(self) -> None:
        # ML OFF — no detection or mitigation running, nothing to protect.
        if not ML_ENABLED:
            return

        cpu_pct, mem_pct = self._sample()
        level = self._classify(cpu_pct, mem_pct)
        self._tier = level

        if level == "CRIT":
            # Tier 3 — install OVS packet-in rate-limit rules.
            self._consecutive_high += 1
            self._throttle_delay = 0.05
            if not self._crit_rules_active:
                log.critical(
                    "ResourceGuard CRIT: CPU=%.1f%% MEM=%.1f%% -- "
                    "installing OVS packet-in rate-limit rules",
                    cpu_pct, mem_pct,
                )
                self._crit_rules_active = self._install_rate_limit_rules()
            elif self._attack_proto != self._installed_proto:
                log.warning(
                    "ResourceGuard: attack proto changed mid-CRIT, old=%s new=%s -- reinstalling",
                    self._installed_proto, self._attack_proto,
                )
                self._remove_rate_limit_rules()
                self._crit_rules_active = self._install_rate_limit_rules()

        elif level == "HIGH":
            # Tier 2 — throttle detection poll rate only.
            # If dropping from CRIT: remove rules, reset counters immediately.
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False
                self._consecutive_high  = 0
                self._throttle_delay    = 0.02
                log.warning(
                    "ResourceGuard HIGH (drop from CRIT): CPU=%.1f%% MEM=%.1f%% -- "
                    "rules removed, throttle reduced to 20ms",
                    cpu_pct, mem_pct,
                )
            else:
                self._consecutive_high += 1
                if self._consecutive_high >= HIGH_CONSECUTIVE_THRESHOLD:
                    self._throttle_delay = 0.02
                    log.warning(
                        "ResourceGuard HIGH (%dx): CPU=%.1f%% MEM=%.1f%% -- "
                        "throttling detection rate (delay=%.0fms)",
                        self._consecutive_high, cpu_pct, mem_pct,
                        self._throttle_delay * 1000,
                    )

        elif level == "WARN":
            # Tier 1 — log only, reset all throttles and rules.
            self._consecutive_high = 0
            self._throttle_delay   = 0.0
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False
            log.warning(
                "ResourceGuard WARN: CPU=%.1f%% MEM=%.1f%%",
                cpu_pct, mem_pct,
            )

        else:
            # NORMAL — reset everything, remove any active rules.
            if self._consecutive_high > 0 or self._throttle_delay > 0 or self._crit_rules_active:
                log.info(
                    "ResourceGuard NORMAL: CPU=%.1f%% MEM=%.1f%% -- "
                    "all throttles removed",
                    cpu_pct, mem_pct,
                )
            self._consecutive_high  = 0
            self._throttle_delay    = 0.0
            if self._crit_rules_active:
                self._remove_rate_limit_rules()
                self._crit_rules_active = False

    def _classify(self, cpu: float, mem: float) -> str:
        if cpu >= CPU_CRIT or mem >= MEM_CRIT: return "CRIT"
        if cpu >= CPU_HIGH or mem >= MEM_HIGH: return "HIGH"
        if cpu >= CPU_WARN or mem >= MEM_WARN: return "WARN"
        return "NORMAL"

    def _sample(self) -> tuple[float, float]:
        # Use controller (Ryu) CPU and memory via monitor._get_ctrl_metrics().
        try:
            from backend.mitigation.monitor import _get_ctrl_metrics
            ctrl_cpu, ctrl_mem_mb = _get_ctrl_metrics()
            # Convert memory MB to % of 150MB practical Ryu ceiling.
            ctrl_mem_pct = min((ctrl_mem_mb / 150.0) * 100.0, 100.0)
            return ctrl_cpu, ctrl_mem_pct
        except Exception as exc:
            log.warning("ResourceGuard: sample error -- %s", exc)
            return 0.0, 0.0

    def _install_rate_limit_rules(self) -> bool:
        # Send proto_block command to Ryu via ZMQ.
        # Returns True only if the rule was actually installed.
        if self._attack_proto is None:
            log.warning("ResourceGuard: no attack proto known -- skipping proto drop")
            return False
        try:
            from backend.mitigation.zmq_commander import commander
            commander.send({"action": "proto_block", "proto": self._attack_proto, "remove": False})
            log.info("ResourceGuard: proto_block sent to Ryu -- nw_proto=%d", self._attack_proto)
            self._installed_proto = self._attack_proto
            return True
        except Exception as exc:
            log.warning("ResourceGuard: failed to send proto_block: %s", exc)
            return False

    def _remove_rate_limit_rules(self) -> None:
        # Send proto_block remove, uses _installed_proto not live _attack_proto.
        if self._installed_proto is None:
            return
        try:
            from backend.mitigation.zmq_commander import commander
            commander.send({"action": "proto_block", "proto": self._installed_proto, "remove": True})
            log.info("ResourceGuard: proto_block removed from Ryu -- nw_proto=%d", self._installed_proto)
        except Exception as exc:
            log.warning("ResourceGuard: failed to send proto_block remove: %s", exc)
        finally:
            self._installed_proto = None

    # Kept for backward compatibility — no longer used internally

    def set_state_machine(self, sm) -> None:
        pass

    def set_deception(self, dec) -> None:
        pass


# Module-level singleton
resource_guard = ResourceGuard()