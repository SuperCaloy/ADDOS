import math
import time
import threading
from collections import deque
from backend.config import TEA_WINDOW_SIZE

import logging
log = logging.getLogger(__name__)

# === ADAPTIVE TEA CONSTANTS ===
# Learning phase: how many intervals to observe before making decisions
TEA_LEARN_INTERVALS   = 30       # ~30s at 1s poll rate — absorbs startup surge
# How many std deviations from learned mean = anomaly
TEA_ATTACK_SIGMA      = 2.5      # diversity drop this far below mean → suspicious
TEA_CROWD_SIGMA       = 1.5      # pkt rate this far above mean → surge
# Minimum absolute diversity to consider flash crowd (not just noise)
TEA_MIN_CROWD_DIVERSITY = 1.0
# EMA alpha for continuous baseline adaptation (after learning phase)
TEA_EMA_ALPHA         = 0.05     # slow adaptation — resistant to attack drift


def _shannon_entropy(values: list[float]) -> float:
    # H = -sum(p * log2(p)) — returns 0 if empty or all zeros
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


class _AdaptiveBaseline:
    """
    Online adaptive baseline for one entropy dimension.
    Phase 1 (learning): collects N intervals, computes mean + std.
    Phase 2 (adaptive): updates mean/std slowly via EMA — resists attack drift.
    """

    def __init__(self, learn_intervals: int, ema_alpha: float):
        self._learn_n   = learn_intervals
        self._alpha     = ema_alpha
        self._samples   = []        # raw samples during learning phase
        self._mean      = None
        self._variance  = None
        self._learned   = False
        self._start_time = time.monotonic()

    @property
    def is_learned(self) -> bool:
        return self._learned

    def push(self, value: float) -> None:
        if not self._learned:
            self._samples.append(value)
            if len(self._samples) >= self._learn_n:
                self._mean     = sum(self._samples) / len(self._samples)
                variance_vals  = [(x - self._mean) ** 2 for x in self._samples]
                self._variance = sum(variance_vals) / len(variance_vals)
                self._learned  = True
                log.info(
                    "TEA baseline learned — mean=%.4f  std=%.4f  (n=%d samples)",
                    self._mean, self._std, len(self._samples)
                )
        else:
            # EMA update — slow adaptation, won't follow attack spikes quickly
            self._mean     = self._alpha * value + (1 - self._alpha) * self._mean
            err            = (value - self._mean) ** 2
            self._variance = self._alpha * err + (1 - self._alpha) * self._variance

    @property
    def mean(self) -> float:
        return self._mean if self._mean is not None else 0.0

    @property
    def _std(self) -> float:
        return math.sqrt(max(self._variance, 1e-9)) if self._variance is not None else 1.0

    def z_score(self, value: float) -> float:
        # How many std devs is value from learned mean
        if not self._learned:
            return 0.0
        return (value - self._mean) / self._std

    def is_low(self, value: float, sigma: float) -> bool:
        # True if value is significantly BELOW learned mean
        return self._learned and self.z_score(value) <= -sigma

    def is_high(self, value: float, sigma: float) -> bool:
        # True if value is significantly ABOVE learned mean
        return self._learned and self.z_score(value) >= sigma


class _SwitchEntropyState:
    # Rolling window + adaptive baselines for one switch
    def __init__(self, window_size: int):
        self.window    = deque(maxlen=window_size)
        self.div_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS, TEA_EMA_ALPHA)
        self.pkt_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS, TEA_EMA_ALPHA)
        self.byt_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS, TEA_EMA_ALPHA)

    def push(self, snapshot: dict) -> None:
        self.window.append(snapshot)
        self.div_base.push(snapshot["diversity_entropy"])
        self.pkt_base.push(snapshot["packetrate_entropy"])
        self.byt_base.push(snapshot["byterate_entropy"])

    def is_ready(self) -> bool:
        return len(self.window) >= 2

    def latest(self) -> dict:
        return self.window[-1]

    def previous(self) -> dict:
        return self.window[-2]

    @property
    def is_learned(self) -> bool:
        return self.div_base.is_learned and self.pkt_base.is_learned


class EntropyAnalyzer:
    """
    Adaptive Temporal Entropy Analysis (TEA).

    Phase 1 — Learning (first ~30 intervals):
      Observes normal traffic entropy, builds mean + std per switch.
      No decisions made during this phase — absorbs startup surge naturally.

    Phase 2 — Adaptive detection:
      Uses learned baseline + z-score thresholds instead of hardcoded values.
      Baselines update slowly via EMA so they track gradual traffic changes
      but resist being pulled by sustained attacks.

    Attack signature:   diversity z-score << -2.5 (collapse) + pkt z-score << -2.5
    Flash crowd signal: diversity z-score normal/high + pkt z-score >> +1.5
    """

    def __init__(self):
        self._lock   = threading.Lock()
        self._states: dict[int, _SwitchEntropyState] = {}

    def update(self, dpid: int, flows: list[dict]) -> dict:
        with self._lock:
            if dpid not in self._states:
                self._states[dpid] = _SwitchEntropyState(TEA_WINDOW_SIZE)
            state = self._states[dpid]

        # Aggregate per-IP pps and bps
        ip_pps: dict[str, float] = {}
        ip_bps: dict[str, float] = {}
        for f in flows:
            src = f.get("src_ip", "")
            if not src or src == "0.0.0.0":
                continue
            ip_pps[src] = ip_pps.get(src, 0.0) + float(f.get("packet_count_per_second", 0))
            ip_bps[src] = ip_bps.get(src, 0.0) + float(f.get("byte_count_per_second",  0))

        diversity_entropy  = _shannon_entropy([1.0] * len(ip_pps))
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
            is_learned = state.is_learned
            div_base   = state.div_base
            pkt_base   = state.pkt_base

            if not state.is_ready():
                return self._neutral(diversity_entropy, packetrate_entropy, learned=False)

            curr = state.latest()
            prev = state.previous()

        diversity_delta  = curr["diversity_entropy"]  - prev["diversity_entropy"]
        packetrate_delta = curr["packetrate_entropy"] - prev["packetrate_entropy"]

        # Still in learning phase — return neutral, no decisions
        if not is_learned:
            log.debug(
                "TEA [dpid=%d] learning phase — interval %d/%d",
                dpid, len(state.window), TEA_LEARN_INTERVALS
            )
            return self._neutral(diversity_entropy, packetrate_entropy, learned=False)

        # === Adaptive thresholds via z-score ===
        div_z  = div_base.z_score(curr["diversity_entropy"])
        pkt_z  = pkt_base.z_score(curr["packetrate_entropy"])

        # Attack: diversity collapses AND packet rate collapses (few IPs dominating)
        diversity_collapsed  = div_base.is_low(curr["diversity_entropy"], TEA_ATTACK_SIGMA)
        packetrate_collapsed = pkt_base.is_low(curr["packetrate_entropy"], TEA_ATTACK_SIGMA)
        is_attack_pattern    = diversity_collapsed and packetrate_collapsed

        # Flash crowd: diversity is normal/high + pkt rate is high + diversity not collapsed
        diversity_normal  = not diversity_collapsed
        packetrate_surge  = pkt_base.is_high(curr["packetrate_entropy"], TEA_CROWD_SIGMA)
        high_diversity    = curr["diversity_entropy"] >= TEA_MIN_CROWD_DIVERSITY
        is_flash_crowd    = diversity_normal and packetrate_surge and high_diversity

        # Confidence
        if is_attack_pattern:
            confidence = "high"
        elif diversity_collapsed or packetrate_collapsed:
            confidence = "moderate"
        else:
            confidence = "low"

        result = {
            "diversity_entropy":  round(curr["diversity_entropy"],  4),
            "packetrate_entropy": round(curr["packetrate_entropy"], 4),
            "diversity_delta":    round(diversity_delta,  4),
            "packetrate_delta":   round(packetrate_delta, 4),
            "diversity_zscore":   round(div_z,  4),
            "packetrate_zscore":  round(pkt_z,  4),
            "baseline_mean_div":  round(div_base.mean, 4),
            "baseline_mean_pkt":  round(pkt_base.mean, 4),
            "unique_ips":         curr["unique_ips"],
            "is_attack_pattern":  is_attack_pattern,
            "is_flash_crowd":     is_flash_crowd,
            "is_learned":         True,
            "confidence":         confidence,
        }

        if is_attack_pattern:
            log.info(
                "TEA [dpid=%d] attack pattern — div_z=%.2f  pkt_z=%.2f  conf=%s",
                dpid, div_z, pkt_z, confidence
            )
        elif is_flash_crowd:
            log.info(
                "TEA [dpid=%d] flash crowd — div=%.3f (normal)  pkt_z=+%.2f (surge)",
                dpid, curr["diversity_entropy"], pkt_z
            )

        return result

    def should_submit(self, tea_result: dict, is_flood_prefilter_flagged: bool) -> bool:
        # Always submit flood-prefiltered IPs
        if is_flood_prefilter_flagged:
            return True

        # Still learning — submit everything so IF can warm up too
        if not tea_result.get("is_learned", False):
            return True

        conf = tea_result.get("confidence", "low")

        # Flash crowd with no prefilter → legit surge, skip ML
        if tea_result.get("is_flash_crowd") and conf != "high":
            log.debug("TEA gate: flash crowd — skipping ML")
            return False

        # Attack pattern → always submit
        if tea_result.get("is_attack_pattern"):
            return True

        # Moderate → submit, let IF decide
        if conf == "moderate":
            return True

        return False

    def reset_switch(self, dpid: int) -> None:
        # Clear state on reconnect — forces re-learning
        with self._lock:
            self._states.pop(dpid, None)
        log.info("TEA [dpid=%d] state reset — re-learning baseline", dpid)

    def _neutral(self, div: float, pkt: float, learned: bool = False) -> dict:
        return {
            "diversity_entropy":  round(div, 4),
            "packetrate_entropy": round(pkt, 4),
            "diversity_delta":    0.0,
            "packetrate_delta":   0.0,
            "diversity_zscore":   0.0,
            "packetrate_zscore":  0.0,
            "baseline_mean_div":  0.0,
            "baseline_mean_pkt":  0.0,
            "unique_ips":         0,
            "is_attack_pattern":  False,
            "is_flash_crowd":     False,
            "is_learned":         learned,
            "confidence":         "low",
        }


# Module-level singleton
entropy_analyzer = EntropyAnalyzer()