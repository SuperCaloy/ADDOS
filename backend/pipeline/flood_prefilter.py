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


class DynamicThreshold:
    """EWMA-based dynamic threshold for DDoS detection."""

    def __init__(self, alpha: float = 0.1, multiplier: float = 3.0,
                 initial: float = 50.0, floor: float = 25.0):
        self.alpha = alpha
        self.multiplier = multiplier
        self.ewma = initial
        self.floor = floor

    def update(self, current_pps: float) -> None:
        self.ewma = (1 - self.alpha) * self.ewma + self.alpha * current_pps

    def threshold(self) -> float:
        return max(self.ewma * self.multiplier, self.floor)

    def tripped(self, current_pps: float) -> bool:
        return current_pps > self.threshold()


# proto_key → (limit, window_seconds)
_PROTO_CONFIG = {
    "SYN":  (FLOOD_SYN_LIMIT,  FLOOD_SYN_WINDOW_S),
    "ICMP": (FLOOD_ICMP_LIMIT, FLOOD_ICMP_WINDOW_S),
    "UDP":  (FLOOD_UDP_LIMIT,  FLOOD_UDP_WINDOW_S),
}

# Burst: trip if 40% of limit arrives within 0.1s or 0.5s sub-window
_BURST_WINDOWS   = [0.1, 0.5]
_BURST_FRACTION  = 0.4
_ACK_POP_MIN_INTERVAL = 0.05

# Correlation: 2+ protocols active simultaneously = multi-vector attack
_CORRELATION_THRESHOLD = 2


class _ProtoWindow:
    # Sliding window of packet arrival times for one src_ip + protocol
    __slots__ = ("times",)

    def __init__(self):
        self.times: list[float] = []

    def record(self, now: float) -> None:
        self.times.append(now)

    def count_recent(self, now: float, window_s: float) -> int:
        # Prune old entries and return count within window
        cutoff = now - window_s
        self.times = [t for t in self.times if t >= cutoff]
        return len(self.times)

    def count_in(self, now: float, window_s: float) -> int:
        # Count within sub-window without pruning
        cutoff = now - window_s
        return sum(1 for t in self.times if t >= cutoff)


class FloodPreFilter:

    def __init__(self):
        self._lock = threading.Lock()

        # src_ip → proto_key → _ProtoWindow
        self._windows: dict[str, dict[str, _ProtoWindow]] = defaultdict(
            lambda: defaultdict(_ProtoWindow)
        )

        # (src_ip, proto_key) → trigger reason string
        self._flagged: dict[tuple, str] = {}

        # IPs detected on multiple protocols at once
        self._correlated: set[str] = set()
        self._ack_pop_ts: dict[str, float] = {}

    def on_packet(self, src_ip: str, proto: str) -> bool:
        # Record one packet; return True only on the first trip
        if proto not in _PROTO_CONFIG:
            return False

        limit, window_s = _PROTO_CONFIG[proto]
        now = time.monotonic()

        with self._lock:
            win   = self._windows[src_ip][proto]
            win.record(now)
            count = win.count_recent(now, window_s)
            key   = (src_ip, proto)

            # Already flagged — update correlation silently
            if key in self._flagged:
                self._check_correlation(src_ip, now)
                return False

            reason = None

            # 1. Full window limit — count >= configured limit in window_s
            if count >= limit:
                reason = f"limit={count}>={limit} in {window_s}s"

            # 2. Burst sub-window — 40% of limit in 0.1s or 0.5s
            if reason is None:
                burst_limit = max(2, int(limit * _BURST_FRACTION))
                for sw in _BURST_WINDOWS:
                    sub_count = win.count_in(now, sw)
                    if sub_count >= burst_limit:
                        reason = f"burst={sub_count}>={burst_limit} in {sw}s"
                        break

            if reason:
                self._flagged[key] = reason
                log.info("FloodPreFilter tripped: %s  proto=%s  reason=%s", src_ip, proto, reason)
                self._check_correlation(src_ip, now)
                return True

        return False

    def _check_correlation(self, src_ip: str, now: float) -> None:
        # Called inside self._lock — count active protocols, log if multi-vector
        active = sum(
            1 for proto, (_, window_s) in _PROTO_CONFIG.items()
            if (w := self._windows[src_ip].get(proto)) and w.count_in(now, window_s) > 0
        )
        if active >= _CORRELATION_THRESHOLD and src_ip not in self._correlated:
            self._correlated.add(src_ip)
            log.info("FloodPreFilter correlation: %s active on %d protocols", src_ip, active)

    def on_ack(self, src_ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._ack_pop_ts.get(src_ip, 0.0) < _ACK_POP_MIN_INTERVAL:
                return
            win = self._windows[src_ip].get("SYN")
            if win and win.times:
                win.times.pop(0)
                self._ack_pop_ts[src_ip] = now

    def is_flagged(self, src_ip: str, proto: str = None) -> bool:
        with self._lock:
            if proto:
                return (src_ip, proto) in self._flagged
            return any((src_ip, p) in self._flagged for p in _PROTO_CONFIG)

    def is_flagged_any(self, src_ip: str) -> bool:
        return self.is_flagged(src_ip, proto=None)

    def is_correlated(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._correlated

    def get_trigger_reason(self, src_ip: str) -> str:
        # Return first matched trigger reason string, or empty string
        with self._lock:
            for proto in _PROTO_CONFIG:
                reason = self._flagged.get((src_ip, proto))
                if reason:
                    return f"{proto}: {reason}"
            return ""

    def clear_flag(self, src_ip: str) -> None:
        # Clear all flags and windows for this IP on release
        with self._lock:
            for proto in _PROTO_CONFIG:
                self._flagged.pop((src_ip, proto), None)
            self._windows.pop(src_ip, None)
            self._ack_pop_ts.pop(src_ip, None)
            self._correlated.discard(src_ip)

    def purge_stale(self) -> None:
        # Remove windows idle longer than 5× the longest window
        now       = time.monotonic()
        max_win   = max(FLOOD_SYN_WINDOW_S, FLOOD_ICMP_WINDOW_S, FLOOD_UDP_WINDOW_S)
        threshold = max_win * 5
        with self._lock:
            stale = [
                ip for ip, proto_map in self._windows.items()
                if all(not w.times or (now - w.times[-1]) > threshold
                       for w in proto_map.values())
            ]
            for ip in stale:
                self._windows.pop(ip, None)
                self._ack_pop_ts.pop(ip, None)
                self._correlated.discard(ip)
                for proto in _PROTO_CONFIG:
                    self._flagged.pop((ip, proto), None)


# Singleton used by zmq_receiver and worker
flood_filter = FloodPreFilter()