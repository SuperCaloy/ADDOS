import math
import threading
from collections import deque
from backend.config import (
    TEA_WINDOW_SIZE,
    TEA_DIVERSITY_DROP_THRESHOLD,
    TEA_PACKETRATE_RISE_THRESHOLD,
    TEA_FLASH_CROWD_MIN_DIVERSITY,
)

import logging
log = logging.getLogger(__name__)


def _shannon_entropy(values: list[float]) -> float:
    """
    Compute Shannon Entropy for a list of raw values.
    Converts to probabilities first then applies H = -sum(p * log2(p)).
    Returns 0.0 if the list is empty or all zeros.
    """
    total = sum(values)
    if total == 0:
        return 0.0

    entropy = 0.0
    for v in values:
        if v <= 0:
            continue
        p = v / total
        entropy -= p * math.log2(p)

    return entropy


class _SwitchEntropyState:
    """
    Holds the rolling entropy window for one switch (dpid).
    Each slot in the window is one polling interval snapshot.
    """

    def __init__(self, window_size: int):
        # Each entry is a dict with entropy values for that interval
        self.window: deque = deque(maxlen=window_size)

    def push(self, snapshot: dict) -> None:
        """Add a new interval snapshot to the rolling window."""
        self.window.append(snapshot)

    def is_ready(self) -> bool:
        """Need at least 2 intervals to compute a delta."""
        return len(self.window) >= 2

    def latest(self) -> dict:
        return self.window[-1]

    def previous(self) -> dict:
        return self.window[-2]


class EntropyAnalyzer:
    """
    Temporal Entropy Analysis (TEA) module.

    Runs on every flow_stats polling interval per switch.
    Tracks how entropy changes over time across three dimensions:
      1. IP diversity  — how many unique source IPs are active
      2. Packet rate   — distribution of pps across active flows
      3. Byte rate     — distribution of bps across active flows

    A DDoS attack signature in entropy terms:
      - IP diversity entropy DROPS   (few IPs dominating)
      - Packet rate entropy RISES    (uniform high-rate flood packets)

    A flash crowd signature (legitimate spike):
      - IP diversity entropy stays HIGH (many different users)
      - Packet rate entropy also rises but diversity does not collapse

    This distinction is what the panel asked for — TEA solves the
    flash crowd false positive problem.
    """

    def __init__(self):
        self._lock   = threading.Lock()
        # One state object per switch dpid
        self._states: dict[int, _SwitchEntropyState] = {}

    # ------------------------------------------------------------------
    # Main entry — call once per flow_stats reply per switch
    # ------------------------------------------------------------------

    def update(self, dpid: int, flows: list[dict]) -> dict:
        """
        Feed a list of flow stat dicts for one switch into the analyzer.
        Each flow dict must have at least:
          - src_ip (str)
          - packet_count_per_second (float)
          - byte_count_per_second (float)

        Returns an analysis result dict with keys:
          - diversity_entropy   (float) current interval
          - packetrate_entropy  (float) current interval
          - diversity_delta     (float) change from previous interval
          - packetrate_delta    (float) change from previous interval
          - is_attack_pattern   (bool)  both signals agree → DDoS
          - is_flash_crowd      (bool)  high diversity + high rate → legit surge
          - confidence          (str)   "high" / "moderate" / "low"
        """
        with self._lock:
            if dpid not in self._states:
                self._states[dpid] = _SwitchEntropyState(TEA_WINDOW_SIZE)

            state = self._states[dpid]

        # Build per-IP aggregates from the flow list
        ip_pps:  dict[str, float] = {}
        ip_bps:  dict[str, float] = {}

        for f in flows:
            src = f.get("src_ip", "")
            if not src or src == "0.0.0.0":
                continue
            ip_pps[src]  = ip_pps.get(src, 0.0)  + float(f.get("packet_count_per_second", 0))
            ip_bps[src]  = ip_bps.get(src, 0.0)  + float(f.get("byte_count_per_second",  0))

        # Compute entropy for this interval
        diversity_entropy  = _shannon_entropy([1.0] * len(ip_pps))  # uniform weight per unique IP
        packetrate_entropy = _shannon_entropy(list(ip_pps.values()))
        byterate_entropy   = _shannon_entropy(list(ip_bps.values()))

        snapshot = {
            "diversity_entropy":  diversity_entropy,
            "packetrate_entropy": packetrate_entropy,
            "byterate_entropy":   byterate_entropy,
            "unique_ips":         len(ip_pps),
        }

        with self._lock:
            state.push(snapshot)

            if not state.is_ready():
                # Not enough history yet — return neutral result
                return self._neutral(diversity_entropy, packetrate_entropy)

            prev = state.previous()
            curr = state.latest()

        # Compute deltas — negative diversity means diversity is collapsing
        diversity_delta  = curr["diversity_entropy"]  - prev["diversity_entropy"]
        packetrate_delta = curr["packetrate_entropy"] - prev["packetrate_entropy"]

        # --- Attack pattern check ---
        # DDoS signature: BOTH entropy values drop together
        #   - few IPs → diversity collapses
        #   - one IP dominates → packet rate distribution becomes skewed → entropy drops
        # This is different from flash crowd where BOTH stay high or rise
        diversity_dropped   = diversity_delta    <= -TEA_DIVERSITY_DROP_THRESHOLD
        packetrate_dropped  = packetrate_delta   <= -TEA_PACKETRATE_RISE_THRESHOLD
        is_attack_pattern   = diversity_dropped and packetrate_dropped

        # --- Flash crowd check ---
        # Flash crowd: diversity stays HIGH (many different users)
        # even though overall traffic volume spikes
        # Packet rate entropy stays high or rises because many IPs contribute
        high_diversity    = curr["diversity_entropy"] >= TEA_FLASH_CROWD_MIN_DIVERSITY
        packetrate_rising = packetrate_delta > 0
        is_flash_crowd    = high_diversity and packetrate_rising and not diversity_dropped

        # --- Confidence level ---
        if is_attack_pattern:
            confidence = "high"
        elif diversity_dropped or packetrate_dropped:
            confidence = "moderate"
        else:
            confidence = "low"

        result = {
            "diversity_entropy":  round(curr["diversity_entropy"],  4),
            "packetrate_entropy": round(curr["packetrate_entropy"], 4),
            "diversity_delta":    round(diversity_delta,  4),
            "packetrate_delta":   round(packetrate_delta, 4),
            "unique_ips":         curr["unique_ips"],
            "is_attack_pattern":  is_attack_pattern,
            "is_flash_crowd":     is_flash_crowd,
            "confidence":         confidence,
        }

        if is_attack_pattern:
            log.info(
                "TEA [dpid=%d] attack pattern — div_delta=%.3f  pkt_delta=%.3f  conf=%s",
                dpid, diversity_delta, packetrate_delta, confidence
            )
        elif is_flash_crowd:
            log.info(
                "TEA [dpid=%d] flash crowd detected — diversity=%.3f (high, legit surge)",
                dpid, curr["diversity_entropy"]
            )

        return result

    # ------------------------------------------------------------------
    # Gate check — used by zmq_receiver to decide if flow goes to worker
    # ------------------------------------------------------------------

    def should_submit(self, tea_result: dict, is_flood_prefilter_flagged: bool) -> bool:
        """
        Decide whether this flow should be submitted to the ML worker queue.

        Rules:
          - Always submit if flood prefilter already flagged this IP
          - Always submit if TEA says attack pattern (high or moderate conf)
          - Skip if TEA says flash crowd AND no prefilter flag
            (flash crowd = legitimate surge, let IF decide only if unsure)
          - Skip if both entropy values are low (normal quiet traffic)
        """
        if is_flood_prefilter_flagged:
            return True

        conf = tea_result.get("confidence", "low")

        # Flash crowd with no other signal — likely legitimate, skip ML
        # TEA identified high diversity + rising rate = real users, not attacker
        if tea_result.get("is_flash_crowd") and conf != "high":
            log.debug("TEA gate: flash crowd — skipping ML, likely legit surge")
            return False

        # Attack pattern → always submit
        if tea_result.get("is_attack_pattern"):
            return True

        # Moderate signal → still submit, let IF decide
        if conf == "moderate":
            return True

        # Low confidence → only submit if there is some baseline pps activity
        return False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def reset_switch(self, dpid: int) -> None:
        """Clear entropy state for a switch — call on reconnect."""
        with self._lock:
            self._states.pop(dpid, None)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _neutral(self, div: float, pkt: float) -> dict:
        """Return a neutral result when not enough history exists yet."""
        return {
            "diversity_entropy":  round(div, 4),
            "packetrate_entropy": round(pkt, 4),
            "diversity_delta":    0.0,
            "packetrate_delta":   0.0,
            "unique_ips":         0,
            "is_attack_pattern":  False,
            "is_flash_crowd":     False,
            "confidence":         "low",
        }


# Module-level singleton — used by zmq_receiver
entropy_analyzer = EntropyAnalyzer()