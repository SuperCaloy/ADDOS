# Proactive resource exhaustion protection and adaptive SDN throttling.
# Monitors controller CPU and memory load, escalating mitigation tiers under severe pressure.
import time
import threading
import logging
from backend.config import ML_ENABLED
from backend.mitigation.ml_scorer import get_top_attacker_ips
from backend.mitigation.mitigation_actions import (
    install_per_ip_meters, remove_per_ip_meters,
)

log = logging.getLogger(__name__)

# Thresholds (%) - proactive response
CPU_WARN  = 70.0
CPU_HIGH  = 80.0
CPU_CRIT  = 90.0
CPU_EMERG = 95.0

MEM_WARN  = 70.0
MEM_HIGH  = 85.0
MEM_CRIT  = 95.0

GUARD_POLL_INTERVAL = 2.0

HIGH_CONSECUTIVE_THRESHOLD = 2
CRIT_CONSECUTIVE_THRESHOLD = 4
EMERG_CONSECUTIVE_THRESHOLD = 6

MIN_DWELL_POLLS = 3

# Graduated per-IP meter rates by escalation tier. All tiers act on ALL
# known attacker IPs. Tier 3 is tight meters, never a blanket proto drop.
TIER_METER_RATE = {1: 50, 2: 25, 3: 10}
MAX_GUARD_IPS = 50
SCORER_FETCH_N = 100


class ResourceGuard:
    def __init__(self):
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._tier = "NORMAL"
        self._throttle_delay = 0.0
        self._consecutive_high = 0
        self._crit_poll_count = 0
        self._crit_rules_active = False
        self._escalation_tier = 0
        self._installed_ips = []
        self._installed_protos = set()
        self._min_dwell_polls = MIN_DWELL_POLLS

    @property
    def throttle_delay(self) -> float:
        return self._throttle_delay

    @property
    def tier(self) -> str:
        return self._tier

    def set_attack_proto(self, attack_class: str) -> None:
        proto_map = {
            "ICMP Flood": 1,
            "SYN Flood": 6,
            "UDP Flood": 17,
        }
        proto = proto_map.get(attack_class)
        if proto is not None:
            with self._lock:
                self._installed_protos.add(proto)

    def _known_attacker_ips(self) -> list[str]:
        # Dynamic candidate set: ALL known attackers, union of ML scorer
        # and state machine, minus whitelist, safety capped.
        from backend.config import WHITELIST_IPS
        seen = []
        try:
            top = get_top_attacker_ips(n=SCORER_FETCH_N) or []
        except Exception:
            top = []
        try:
            from backend.mitigation.state_machine import state_machine
            active = state_machine.get_state_ips() or []
        except Exception:
            active = []
        for ip in list(top) + list(active):
            if ip in WHITELIST_IPS:
                continue
            if ip not in seen:
                seen.append(ip)
            if len(seen) >= MAX_GUARD_IPS:
                break
        return seen

    def _reconcile_meters(self, rate_pps: int) -> None:
        # Refresh installed set when membership changes. No churn when unchanged.
        fresh = self._known_attacker_ips()
        if set(fresh) == set(self._installed_ips):
            return
        remove_per_ip_meters()
        if fresh:
            install_per_ip_meters(fresh, rate_pps=rate_pps)
        self._installed_ips = fresh

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="resource-guard", daemon=True)
        self._thread.start()
        log.info("ResourceGuard started: poll=%.0fs CPU warn/high/crit/emerg=%.0f/%.0f/%.0f/%.0f%%",
                 GUARD_POLL_INTERVAL, CPU_WARN, CPU_HIGH, CPU_CRIT, CPU_EMERG)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                self._check()
            except Exception as exc:
                log.warning("ResourceGuard error: %s", exc)
            time.sleep(GUARD_POLL_INTERVAL)

    def _check(self) -> None:
        if not ML_ENABLED:
            return

        cpu_pct, mem_pct = self._sample()
        level = self._classify(cpu_pct, mem_pct)
        self._tier = level

        with self._lock:
            if level == "EMERGENCY":
                self._handle_emergency()
            elif level == "CRIT":
                self._handle_crit()
            elif level == "HIGH":
                self._handle_high()
            else:
                self._handle_normal()

    def _handle_emergency(self) -> None:
        self._consecutive_high += 1
        self._throttle_delay = 0.05
        self._crit_poll_count = 0

        if not self._crit_rules_active and self._consecutive_high >= 2:
            ips = self._known_attacker_ips()
            if ips and install_per_ip_meters(ips, rate_pps=TIER_METER_RATE[3]):
                self._crit_rules_active = True
                self._installed_ips = ips
                self._escalation_tier = 3
        elif self._escalation_tier == 2 and self._consecutive_high >= EMERG_CONSECUTIVE_THRESHOLD:
            log.critical("ResourceGuard: escalating to tier 3 (tight per-IP meters)")
            remove_per_ip_meters()
            ips = self._known_attacker_ips()
            if ips:
                install_per_ip_meters(ips, rate_pps=TIER_METER_RATE[3])
                self._installed_ips = ips
            self._escalation_tier = 3
        elif self._crit_rules_active:
            self._reconcile_meters(TIER_METER_RATE[3])

    def _handle_crit(self) -> None:
        self._consecutive_high += 1
        self._crit_poll_count += 1
        self._throttle_delay = 0.05

        if not self._crit_rules_active and self._consecutive_high >= CRIT_CONSECUTIVE_THRESHOLD:
            ips = self._known_attacker_ips()
            if ips and install_per_ip_meters(ips, rate_pps=TIER_METER_RATE[2]):
                self._crit_rules_active = True
                self._installed_ips = ips
                self._escalation_tier = 2
        elif self._escalation_tier == 1 and self._consecutive_high >= CRIT_CONSECUTIVE_THRESHOLD:
            log.warning("ResourceGuard: escalating to tier 2 (tighter meters)")
            remove_per_ip_meters()
            ips = self._known_attacker_ips()
            if ips and install_per_ip_meters(ips, rate_pps=TIER_METER_RATE[2]):
                self._crit_rules_active = True
                self._installed_ips = ips
                self._escalation_tier = 2
        elif self._crit_rules_active:
            self._reconcile_meters(TIER_METER_RATE[2])

    def _handle_high(self) -> None:
        self._consecutive_high += 1
        self._crit_poll_count = 0
        self._throttle_delay = 0.02

        if not self._crit_rules_active and self._consecutive_high >= HIGH_CONSECUTIVE_THRESHOLD:
            ips = self._known_attacker_ips()
            if ips and install_per_ip_meters(ips, rate_pps=TIER_METER_RATE[1]):
                self._crit_rules_active = True
                self._installed_ips = ips
                self._escalation_tier = 1
        elif self._crit_rules_active:
            self._reconcile_meters(TIER_METER_RATE[1])

    def _handle_normal(self) -> None:
        if self._crit_rules_active:
            if self._crit_poll_count >= self._min_dwell_polls:
                remove_per_ip_meters()
                self._crit_rules_active = False
                self._consecutive_high = 0
                self._crit_poll_count = 0
                self._escalation_tier = 0
                self._installed_ips = []
                self._installed_protos.clear()
        else:
            self._consecutive_high = 0
            self._crit_poll_count = 0
            self._throttle_delay = 0.0

    def _classify(self, cpu: float, mem: float) -> str:
        if cpu >= CPU_EMERG or mem >= MEM_CRIT:
            return "EMERGENCY"
        if cpu >= CPU_CRIT or mem >= MEM_CRIT:
            return "CRIT"
        if cpu >= CPU_HIGH or mem >= MEM_HIGH:
            return "HIGH"
        if cpu >= CPU_WARN or mem >= MEM_WARN:
            return "WARN"
        return "NORMAL"

    def _sample(self) -> tuple[float, float]:
        try:
            from backend.mitigation.monitor import _get_ctrl_metrics
            ctrl_cpu, ctrl_mem_mb = _get_ctrl_metrics()
            ctrl_mem_pct = min((ctrl_mem_mb / 150.0) * 100.0, 100.0)
            return ctrl_cpu, ctrl_mem_pct
        except Exception as exc:
            log.warning("ResourceGuard: sample error: %s", exc)
            return 0.0, 0.0



resource_guard = ResourceGuard()
