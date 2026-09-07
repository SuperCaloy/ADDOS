import time
import threading
import logging
from backend.config import ML_ENABLED
from backend.mitigation.ml_scorer import get_top_attacker_ips
from backend.mitigation.mitigation_actions import (
    install_per_ip_meters, remove_per_ip_meters,
    install_proto_block, remove_proto_block,
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

    @property
    def throttle_delay(self) -> float:
        return self._throttle_delay

    @property
    def is_paused(self) -> bool:
        return False

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

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="resource-guard", daemon=True)
        self._thread.start()
        log.info("ResourceGuard started -- poll=%.0fs CPU warn/high/crit/emerg=%.0f/%.0f/%.0f/%.0f%%",
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
            top_ips = get_top_attacker_ips(n=20)
            if top_ips:
                success = install_per_ip_meters(top_ips, rate_pps=50)
                if success:
                    self._crit_rules_active = True
                    self._installed_ips = top_ips
                    self._escalation_tier = 2
                else:
                    install_proto_block(self._installed_protos)
                    self._crit_rules_active = True
                    self._escalation_tier = 3
            else:
                install_proto_block(self._installed_protos)
                self._crit_rules_active = True
                self._escalation_tier = 3
        elif self._escalation_tier == 2 and self._consecutive_high >= EMERG_CONSECUTIVE_THRESHOLD:
            log.critical("ResourceGuard: escalating to tier 3 (blanket proto_block)")
            remove_per_ip_meters()
            install_proto_block(self._installed_protos)
            self._escalation_tier = 3

    def _handle_crit(self) -> None:
        self._consecutive_high += 1
        self._crit_poll_count += 1
        self._throttle_delay = 0.05

        if not self._crit_rules_active and self._consecutive_high >= CRIT_CONSECUTIVE_THRESHOLD:
            top_ips = get_top_attacker_ips(n=15)
            if top_ips:
                success = install_per_ip_meters(top_ips, rate_pps=75)
                if success:
                    self._crit_rules_active = True
                    self._installed_ips = top_ips
                    self._escalation_tier = 2
        elif self._escalation_tier == 1 and self._consecutive_high >= CRIT_CONSECUTIVE_THRESHOLD:
            log.warning("ResourceGuard: escalating to tier 2 (tighter meters)")
            remove_per_ip_meters()
            top_ips = get_top_attacker_ips(n=15)
            if top_ips:
                success = install_per_ip_meters(top_ips, rate_pps=75)
                if success:
                    self._crit_rules_active = True
                    self._installed_ips = top_ips
                    self._escalation_tier = 2

    def _handle_high(self) -> None:
        self._consecutive_high += 1
        self._crit_poll_count = 0
        self._throttle_delay = 0.02

        if not self._crit_rules_active and self._consecutive_high >= HIGH_CONSECUTIVE_THRESHOLD:
            top_ips = get_top_attacker_ips(n=10)
            if top_ips:
                success = install_per_ip_meters(top_ips, rate_pps=100)
                if success:
                    self._crit_rules_active = True
                    self._installed_ips = top_ips
                    self._escalation_tier = 1

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
            log.warning("ResourceGuard: sample error -- %s", exc)
            return 0.0, 0.0

    def set_state_machine(self, sm) -> None:
        pass

    def set_deception(self, dec) -> None:
        pass


resource_guard = ResourceGuard()
