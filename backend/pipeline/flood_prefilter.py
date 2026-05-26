import time
import threading
from collections import defaultdict
from backend.config import (
    FLOOD_SYN_LIMIT,  FLOOD_SYN_WINDOW_S,
    FLOOD_ICMP_LIMIT, FLOOD_ICMP_WINDOW_S,
    FLOOD_UDP_LIMIT,  FLOOD_UDP_WINDOW_S,
)

import logging
log = logging.getLogger(__name__)


# --- Per-protocol config bundled together for easy lookup ---
# proto_key → (limit, window_seconds)
_PROTO_CONFIG = {
    "SYN":  (FLOOD_SYN_LIMIT,  FLOOD_SYN_WINDOW_S),
    "ICMP": (FLOOD_ICMP_LIMIT, FLOOD_ICMP_WINDOW_S),
    "UDP":  (FLOOD_UDP_LIMIT,  FLOOD_UDP_WINDOW_S),
}

# Burst sub-windows — checked in addition to full window
# If any sub-window fills to (limit * sub_fraction), trip immediately
_BURST_WINDOWS = [0.1, 0.5]   # seconds
_BURST_FRACTION = 0.4          # 40% of limit in a sub-window = burst

# Protocol correlation — if IP trips this many protocols simultaneously, boost confidence
_CORRELATION_THRESHOLD = 2     # 2+ protocols at once = multi-vector attack

# Rate acceleration — flag if second-half rate is this many times the first-half rate
_ACCEL_FACTOR = 2.0            # rate doubled over observation window = accelerating


class _ProtoWindow:
    # Tracks packet arrival times for one src_ip + one protocol
    __slots__ = ("times",)

    def __init__(self):
        self.times: list[float] = []

    def record(self, now: float) -> None:
        self.times.append(now)

    def count_recent(self, now: float, window_s: float) -> int:
        cutoff = now - window_s
        self.times = [t for t in self.times if t >= cutoff]
        return len(self.times)

    def count_in(self, now: float, window_s: float) -> int:
        """Count packets within a specific sub-window without pruning."""
        cutoff = now - window_s
        return sum(1 for t in self.times if t >= cutoff)

    def is_accelerating(self, now: float, window_s: float) -> bool:
        """
        Compare second-half rate vs first-half rate within the window.
        Returns True if rate doubled — indicates ramp-up attack pattern.
        """
        cutoff  = now - window_s
        recent  = [t for t in self.times if t >= cutoff]
        n = len(recent)
        if n < 6:
            return False
        mid      = now - window_s / 2
        first    = sum(1 for t in recent if t < mid)
        second   = sum(1 for t in recent if t >= mid)
        half_dur = window_s / 2
        rate_first  = first  / half_dur
        rate_second = second / half_dur
        return rate_first > 0 and (rate_second / rate_first) >= _ACCEL_FACTOR


class FloodPreFilter:
    """
    Generalized flood pre-filter for SYN, ICMP, and UDP.

    Detection methods (any one can trip the flag):
    1. Limit hit      — packet count >= limit within full window (original)
    2. Burst          — 40% of limit within 0.1s or 0.5s sub-window
    3. Acceleration   — packet rate doubled over observation window
    4. Correlation    — same IP active on 2+ protocols simultaneously

    Flagged IPs get a confidence_boost field so worker/decision_engine
    can weight them more aggressively in the ML pipeline.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Nested dict: src_ip → proto_key → _ProtoWindow
        self._windows: dict[str, dict[str, _ProtoWindow]] = defaultdict(
            lambda: defaultdict(_ProtoWindow)
        )

        # (src_ip, proto_key) → trigger reason string
        self._flagged: dict[tuple, str] = {}

        # src_ip → True if multi-protocol correlation detected
        self._correlated: set[str] = set()

    # ------------------------------------------------------------------
    # Main entry — call this on every packet_in event
    # ------------------------------------------------------------------

    def on_packet(self, src_ip: str, proto: str) -> bool:
        """
        Record one packet for this src_ip + protocol.
        Returns True the first time any detection method trips.
        Returns False for all packets before and after the trigger.
        """
        if proto not in _PROTO_CONFIG:
            return False

        limit, window_s = _PROTO_CONFIG[proto]
        now = time.monotonic()

        with self._lock:
            win   = self._windows[src_ip][proto]
            win.record(now)
            count = win.count_recent(now, window_s)
            key   = (src_ip, proto)

            # Already flagged — check correlation silently and return
            if key in self._flagged:
                self._check_correlation(src_ip, now)
                return False

            reason = None

            # 1. Full window limit hit
            if count >= limit:
                reason = f"limit={count}>={limit} in {window_s}s"

            # 2. Burst detection — any sub-window fills fast
            if reason is None:
                burst_limit = max(2, int(limit * _BURST_FRACTION))
                for sw in _BURST_WINDOWS:
                    sub_count = win.count_in(now, sw)
                    if sub_count >= burst_limit:
                        reason = f"burst={sub_count}>={burst_limit} in {sw}s"
                        break

            # 3. Rate acceleration
            if reason is None and win.is_accelerating(now, window_s):
                reason = f"acceleration x{_ACCEL_FACTOR} in {window_s}s"

            if reason:
                self._flagged[key] = reason
                log.info(
                    "FloodPreFilter tripped: %s  proto=%s  reason=%s",
                    src_ip, proto, reason
                )
                # Check correlation after flagging
                self._check_correlation(src_ip, now)
                return True

        return False

    def _check_correlation(self, src_ip: str, now: float) -> None:
        """
        Check if this IP is active on multiple protocols simultaneously.
        Called inside self._lock — do not re-acquire.
        """
        active_protos = 0
        for proto, (limit, window_s) in _PROTO_CONFIG.items():
            win = self._windows[src_ip].get(proto)
            if win and win.count_in(now, window_s) > 0:
                active_protos += 1

        if active_protos >= _CORRELATION_THRESHOLD and src_ip not in self._correlated:
            self._correlated.add(src_ip)
            log.info(
                "FloodPreFilter correlation: %s active on %d protocols simultaneously",
                src_ip, active_protos
            )

    # ------------------------------------------------------------------
    # SYN ACK — removes one half-open entry
    # ------------------------------------------------------------------

    def on_ack(self, src_ip: str) -> None:
        with self._lock:
            win = self._windows[src_ip].get("SYN")
            if win and win.times:
                win.times.pop(0)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_flagged(self, src_ip: str, proto: str = None) -> bool:
        with self._lock:
            if proto:
                return (src_ip, proto) in self._flagged
            return any((src_ip, p) in self._flagged for p in _PROTO_CONFIG)

    def is_flagged_any(self, src_ip: str) -> bool:
        return self.is_flagged(src_ip, proto=None)

    def is_correlated(self, src_ip: str) -> bool:
        """Returns True if this IP was detected on multiple protocols at once."""
        with self._lock:
            return src_ip in self._correlated

    def get_trigger_reason(self, src_ip: str) -> str:
        """Returns the trigger reason string for the first flagged protocol, or ''."""
        with self._lock:
            for proto in _PROTO_CONFIG:
                reason = self._flagged.get((src_ip, proto))
                if reason:
                    return f"{proto}: {reason}"
            return ""

    def clear_flag(self, src_ip: str) -> None:
        """Clear all flags and windows for this IP — call on release."""
        with self._lock:
            for proto in _PROTO_CONFIG:
                self._flagged.pop((src_ip, proto), None)
            self._windows.pop(src_ip, None)
            self._correlated.discard(src_ip)

    # ------------------------------------------------------------------
    # Cleanup — call this periodically to free memory
    # ------------------------------------------------------------------

    def purge_stale(self) -> None:
        """Remove windows that have had no packets for a long time."""
        now = time.monotonic()
        with self._lock:
            stale_ips = []
            for src_ip, proto_map in self._windows.items():
                all_old = all(
                    not w.times or (now - w.times[-1]) > max(
                        FLOOD_SYN_WINDOW_S,
                        FLOOD_ICMP_WINDOW_S,
                        FLOOD_UDP_WINDOW_S
                    ) * 5
                    for w in proto_map.values()
                )
                if all_old:
                    stale_ips.append(src_ip)

            for src_ip in stale_ips:
                self._windows.pop(src_ip, None)
                self._correlated.discard(src_ip)
                for proto in _PROTO_CONFIG:
                    self._flagged.pop((src_ip, proto), None)


# Module-level singleton — used by zmq_receiver and worker
flood_filter = FloodPreFilter()