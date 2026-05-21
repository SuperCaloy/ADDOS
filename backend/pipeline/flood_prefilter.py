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


class _ProtoWindow:
    # Tracks packet arrival times for one src_ip + one protocol
    __slots__ = ("times",)

    def __init__(self):
        self.times: list[float] = []

    def record(self, now: float) -> None:
        self.times.append(now)

    def count_recent(self, now: float, window_s: float) -> int:
        # Drop timestamps older than the window then return what is left
        cutoff = now - window_s
        self.times = [t for t in self.times if t >= cutoff]
        return len(self.times)


class FloodPreFilter:
    """
    Generalized flood pre-filter for SYN, ICMP, and UDP.

    Counts packet_in events per src_ip per protocol inside a sliding
    time window. When the count hits the limit the IP is flagged right
    away — no need to wait for the 1-second stats poll.

    The IF/RF pipeline still runs on flagged IPs — this is just an
    early-warning fast path, not a replacement for ML.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Nested dict: src_ip → proto_key → _ProtoWindow
        self._windows: dict[str, dict[str, _ProtoWindow]] = defaultdict(
            lambda: defaultdict(_ProtoWindow)
        )

        # Set of (src_ip, proto_key) pairs that have tripped the limit
        self._flagged: set[tuple] = set()

    # ------------------------------------------------------------------
    # Main entry — call this on every packet_in event
    # ------------------------------------------------------------------

    def on_packet(self, src_ip: str, proto: str) -> bool:
        """
        Record one packet for this src_ip + protocol.
        Returns True the first time the limit is hit (trigger moment).
        Returns False for all packets before and after the trigger.
        """
        if proto not in _PROTO_CONFIG:
            # We only track SYN, ICMP, UDP
            return False

        limit, window_s = _PROTO_CONFIG[proto]
        now = time.monotonic()

        with self._lock:
            win = self._windows[src_ip][proto]
            win.record(now)
            count = win.count_recent(now, window_s)

            key = (src_ip, proto)
            if count >= limit and key not in self._flagged:
                self._flagged.add(key)
                log.info(
                    "FloodPreFilter tripped: %s  proto=%s  count=%d in %.1fs",
                    src_ip, proto, count, window_s
                )
                return True

        return False

    # ------------------------------------------------------------------
    # SYN ACK — removes one half-open entry (same as old syn_prefilter)
    # ------------------------------------------------------------------

    def on_ack(self, src_ip: str) -> None:
        """Call this when a TCP ACK arrives to reduce the SYN half-open count."""
        with self._lock:
            win = self._windows[src_ip].get("SYN")
            if win and win.times:
                win.times.pop(0)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_flagged(self, src_ip: str, proto: str = None) -> bool:
        """
        Check if an IP is flagged.
        If proto is given, checks only that protocol.
        If proto is None, checks any protocol.
        """
        with self._lock:
            if proto:
                return (src_ip, proto) in self._flagged
            # Check all protocols for this IP
            return any((src_ip, p) in self._flagged for p in _PROTO_CONFIG)

    def is_flagged_any(self, src_ip: str) -> bool:
        """Returns True if this IP is flagged for any protocol."""
        return self.is_flagged(src_ip, proto=None)

    def clear_flag(self, src_ip: str) -> None:
        """Clear all flags and windows for this IP — call on release."""
        with self._lock:
            for proto in _PROTO_CONFIG:
                self._flagged.discard((src_ip, proto))
            self._windows.pop(src_ip, None)

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
                # Also clear flags for this IP
                for proto in _PROTO_CONFIG:
                    self._flagged.discard((src_ip, proto))


# Module-level singleton — used by zmq_receiver and worker
flood_filter = FloodPreFilter()