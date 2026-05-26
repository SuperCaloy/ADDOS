import time
import threading
import logging
import datetime
from dataclasses import dataclass, field
from typing import Optional

from backend.database import writer

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────
# Silent dummy host — must match h21 in topology.py
SINKHOLE_IP = "10.0.0.21"

# Observation window before escalate/release decision
SINKHOLE_OBSERVE_SECONDS = 30.0

# PPS above this after observation window → escalate to Phase 1
SINKHOLE_PPS_ESCALATE_THRESHOLD = 1.0


@dataclass
class SinkholeEntry:
    src_ip:        str
    attack_vector: str
    if_score:      float
    confidence:    float
    entered_at:    float = field(default_factory=time.monotonic)
    recent_pps:    float = 0.0
    first_seen:    str   = field(
        default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    def elapsed(self) -> float:
        return time.monotonic() - self.entered_at

    def observation_complete(self) -> bool:
        return self.elapsed() >= SINKHOLE_OBSERVE_SECONDS


class DeceptionModule:
    # Manages sinkhole observation for uncertain / low-confidence IPs.
    #
    # Flow:
    #   1. state_machine calls enter_sinkhole() for uncertain IPs
    #   2. ZmqCommander sends redirect FlowMod → traffic goes to h21
    #   3. tick() checks observation windows every second
    #   4. After SINKHOLE_OBSERVE_SECONDS:
    #        pps still elevated → escalate_callback → Phase 1
    #        pps dropped        → release_callback  → clear rules

    def __init__(self):
        self._lock              = threading.Lock()
        self._entries: dict[str, SinkholeEntry] = {}
        self._commander         = None
        self._escalate_callback = None
        self._release_callback  = None

    def set_commander(self, commander) -> None:
        self._commander = commander

    def set_callbacks(self, escalate_fn, release_fn) -> None:
        # escalate_fn(src_ip, if_score, attack_vector, confidence) → Phase 1
        # release_fn(src_ip) → clear rules
        self._escalate_callback = escalate_fn
        self._release_callback  = release_fn

    # ── Public ─────────────────────────────────────────────────────────

    def enter_sinkhole(self, src_ip: str, attack_vector: str,
                       if_score: float, confidence: float) -> bool:
        # Place IP into sinkhole observation and send redirect FlowMod.
        # Returns False if IP is already in sinkhole.
        with self._lock:
            if src_ip in self._entries:
                log.debug("Deception: %s already in sinkhole", src_ip)
                return False

            entry = SinkholeEntry(
                src_ip        = src_ip,
                attack_vector = attack_vector,
                if_score      = if_score,
                confidence    = confidence,
            )
            self._entries[src_ip] = entry

        self._push_redirect(src_ip)

        log.info("Deception: sinkhole — %s  vector=%s  conf=%.2f  observe=%ds  →%s",
                 src_ip, attack_vector, confidence, SINKHOLE_OBSERVE_SECONDS, SINKHOLE_IP)

        writer.log_mitigation_event({
            "timestamp":       entry.first_seen,
            "src_ip":          src_ip,
            "predicted_class": "DDoS",
            "attack_vector":   attack_vector,
            "confidence":      confidence,
            "priority":        "Low",
            "action_taken":    f"Sinkhole (redirect→{SINKHOLE_IP})",
            "if_score":        if_score,
            "phase":           "Deception — Sinkhole Observation",
            "is_manual":       False,
        })

        return True

    def update_pps(self, src_ip: str, pps: float) -> None:
        # Update recent PPS for a sinkholes IP.
        # Called by decision_engine on each flow result.
        with self._lock:
            if src_ip in self._entries:
                self._entries[src_ip].recent_pps = pps

    def is_sinkholes(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._entries

    def get_active_list(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "src_ip":        e.src_ip,
                    "attack_vector": e.attack_vector,
                    "if_score":      round(e.if_score, 4),
                    "confidence":    f"{e.confidence * 100:.1f}%",
                    "elapsed_sec":   int(e.elapsed()),
                    "remaining_sec": max(0, int(SINKHOLE_OBSERVE_SECONDS - e.elapsed())),
                    "recent_pps":    round(e.recent_pps, 2),
                    "phase":         "Deception — Sinkhole",
                }
                for e in self._entries.values()
            ]

    def emergency_clear(self) -> int:
        # Public method for resource_guard — clears all sinkhole entries.
        # Returns count of cleared IPs.
        # resource_guard must never access private _lock/_entries directly.
        with self._lock:
            sinkhole_ips = list(self._entries.keys())
            self._entries.clear()
        for ip in sinkhole_ips:
            self._push_clear(ip)
        if sinkhole_ips:
            log.info("Deception: emergency cleared %d sinkhole entries", len(sinkhole_ips))
        return len(sinkhole_ips)

    # ── Tick ───────────────────────────────────────────────────────────

    def tick(self) -> None:
        # Called every second by the tick thread.
        # Processes entries whose observation window has completed.
        with self._lock:
            to_process = [e for e in self._entries.values() if e.observation_complete()]

        for entry in to_process:
            self._evaluate(entry)

    def _evaluate(self, entry: SinkholeEntry) -> None:
        # After observation window: escalate to Phase 1 or release.
        # pps > threshold → escalate
        # pps <= threshold → release
        src_ip = entry.src_ip

        with self._lock:
            self._entries.pop(src_ip, None)

        if entry.recent_pps > SINKHOLE_PPS_ESCALATE_THRESHOLD:
            log.info("Deception: %s → Phase 1  pps=%.1f", src_ip, entry.recent_pps)
            if self._escalate_callback:
                self._escalate_callback(
                    src_ip        = src_ip,
                    if_score      = entry.if_score,
                    attack_vector = entry.attack_vector,
                    confidence    = entry.confidence,
                )
            else:
                self._push_clear(src_ip)
        else:
            log.info("Deception: %s → released (traffic stopped)  pps=%.1f",
                     src_ip, entry.recent_pps)
            self._push_clear(src_ip)
            if self._release_callback:
                self._release_callback(src_ip)

    # ── Internal ───────────────────────────────────────────────────────

    def _push_redirect(self, src_ip: str) -> None:
        if self._commander:
            self._commander.send({
                "action":      "redirect",
                "src_ip":      src_ip,
                "redirect_to": SINKHOLE_IP,
            })

    def _push_clear(self, src_ip: str) -> None:
        if self._commander:
            self._commander.send({"action": "clear", "src_ip": src_ip})


# Module-level singleton
deception = DeceptionModule()