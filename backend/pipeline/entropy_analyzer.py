import math
import time
import threading
from collections import deque
from backend.config import TEA_WINDOW_SIZE

import logging
log = logging.getLogger(__name__)

# === ADAPTIVE TEA CONSTANTS ===
# Learning phase: maximum intervals — learning stops early if variance stabilizes
TEA_LEARN_INTERVALS   = 30       # upper bound; may finish sooner if traffic is stable
# How many std deviations from learned mean = anomaly
# These are base values — actual sigma scales dynamically with baseline stability
TEA_ATTACK_SIGMA      = 2.5      # base: diversity drop this far below mean → suspicious
TEA_CROWD_SIGMA       = 1.5      # base: pkt rate this far above mean → surge
# Minimum absolute diversity to consider flash crowd (not just noise)
# Dynamic: set to fraction of learned baseline mean after learning phase
TEA_MIN_CROWD_DIVERSITY = 1.0    # fallback before learning completes
# EMA alpha bounds — actual alpha scales with baseline stability
TEA_EMA_ALPHA_MIN     = 0.02     # slowest adaptation (noisy/unstable traffic)
TEA_EMA_ALPHA_MAX     = 0.10     # fastest adaptation (very stable traffic)
# Variance stability threshold — learning ends early when variance change < this
TEA_VARIANCE_STABLE_THRESHOLD = 0.01
# Robust EMA: reject samples this many dynamic-sigma away from mean
TEA_ROBUST_REJECT_SIGMA = 3.0


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

    Learning phase: collects up to TEA_LEARN_INTERVALS samples but stops early
    if variance stabilizes — avoids a rigid 30s blind window on stable traffic.

    Adaptive phase:
    - Dynamic alpha: faster updates when traffic is stable (low variance),
      slower when noisy (high variance) — self-tuning adaptation speed.
    - Robust EMA: rejects samples beyond TEA_ROBUST_REJECT_SIGMA * dynamic_sigma
      from the mean — attack spikes never drift the baseline.
    - IF feedback lock: external confirm_attack() freezes updates entirely;
      confirm_normal() re-enables them — only IF-confirmed normal traffic
      touches the baseline.
    """

    def __init__(self, learn_intervals: int):
        self._learn_n      = learn_intervals
        self._samples      = []
        self._mean         = None
        self._variance     = None
        self._learned      = False
        self._alpha        = TEA_EMA_ALPHA_MIN   # starts slow, adjusts after learning
        self._locked        = False              # True = IF confirmed attack, freeze updates

    @property
    def is_learned(self) -> bool:
        return self._learned

    def _compute_alpha(self) -> float:
        # Dynamic alpha: inversely proportional to relative variance
        # Low variance (stable) → alpha closer to MAX (faster adaptation)
        # High variance (noisy) → alpha closer to MIN (slower adaptation)
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_EMA_ALPHA_MIN
        cv = math.sqrt(max(self._variance, 1e-9)) / (abs(self._mean) + 1e-9)
        # cv near 0 = stable → alpha MAX; cv large = noisy → alpha MIN
        alpha = TEA_EMA_ALPHA_MAX - cv * (TEA_EMA_ALPHA_MAX - TEA_EMA_ALPHA_MIN)
        return max(TEA_EMA_ALPHA_MIN, min(TEA_EMA_ALPHA_MAX, alpha))

    def _variance_stable(self) -> bool:
        # Check if last few samples have stabilized — early learning stop
        n = len(self._samples)
        if n < 10:
            return False
        recent   = self._samples[-5:]
        older    = self._samples[-10:-5]
        var_new  = sum((x - sum(recent) / len(recent)) ** 2 for x in recent) / len(recent)
        var_old  = sum((x - sum(older)  / len(older))  ** 2 for x in older)  / len(older)
        return abs(var_new - var_old) < TEA_VARIANCE_STABLE_THRESHOLD

    def push(self, value: float) -> None:
        if not self._learned:
            self._samples.append(value)
            # Early stop: variance stabilized OR hit max intervals
            ready = (
                len(self._samples) >= self._learn_n or
                self._variance_stable()
            )
            if ready and len(self._samples) >= 10:
                self._mean     = sum(self._samples) / len(self._samples)
                variance_vals  = [(x - self._mean) ** 2 for x in self._samples]
                self._variance = sum(variance_vals) / len(variance_vals)
                self._alpha    = self._compute_alpha()
                self._learned  = True
                log.info(
                    "TEA baseline learned — mean=%.4f  std=%.4f  alpha=%.4f  (n=%d samples)",
                    self._mean, self._std, self._alpha, len(self._samples)
                )
            return

        # IF feedback lock — IF confirmed attack, freeze baseline
        if self._locked:
            return

        # Robust EMA — reject outliers beyond dynamic sigma threshold
        z = abs(value - self._mean) / self._std
        if z >= TEA_ROBUST_REJECT_SIGMA:
            log.debug("TEA robust reject: value=%.4f  z=%.2f >= %.1f", value, z, TEA_ROBUST_REJECT_SIGMA)
            return

        # Dynamic alpha — recalculate each update based on current variance
        self._alpha    = self._compute_alpha()
        self._mean     = self._alpha * value + (1 - self._alpha) * self._mean
        err            = (value - self._mean) ** 2
        self._variance = self._alpha * err + (1 - self._alpha) * self._variance

    def lock(self) -> None:
        """IF confirmed attack — freeze baseline updates."""
        self._locked = True

    def unlock(self) -> None:
        """IF confirmed normal — resume baseline updates."""
        self._locked = False

    @property
    def mean(self) -> float:
        return self._mean if self._mean is not None else 0.0

    @property
    def _std(self) -> float:
        return math.sqrt(max(self._variance, 1e-9)) if self._variance is not None else 1.0

    def dynamic_attack_sigma(self) -> float:
        # Tighten sigma when baseline is stable (low cv), loosen when noisy
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_ATTACK_SIGMA
        cv = self._std / (abs(self._mean) + 1e-9)
        # stable (cv~0) → tighten to 2.0; noisy (cv large) → loosen to 3.5
        sigma = TEA_ATTACK_SIGMA + cv * 1.5
        return max(2.0, min(3.5, sigma))

    def dynamic_crowd_sigma(self) -> float:
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_CROWD_SIGMA
        cv = self._std / (abs(self._mean) + 1e-9)
        sigma = TEA_CROWD_SIGMA + cv * 1.0
        return max(1.2, min(2.5, sigma))

    def z_score(self, value: float) -> float:
        if not self._learned:
            return 0.0
        return (value - self._mean) / self._std

    def is_low(self, value: float, sigma: float) -> bool:
        return self._learned and self.z_score(value) <= -sigma

    def is_high(self, value: float, sigma: float) -> bool:
        return self._learned and self.z_score(value) >= sigma


class _SwitchEntropyState:
    # Rolling window + adaptive baselines for one switch
    def __init__(self, window_size: int):
        self.window    = deque(maxlen=window_size)
        self.div_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.pkt_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.byt_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS)

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


# Min samples before making a verdict
IP_PROFILE_MIN_SAMPLES = 5
# Rolling window size for per-IP observation
IP_PROFILE_WINDOW      = 20


class _IpEntropyProfile:
    # Tracks one IP's pps trend + entropy during observation (Quarantine or Sinkhole)

    def __init__(self):
        # Rolling pps and bps samples
        self._pps_samples = deque(maxlen=IP_PROFILE_WINDOW)
        self._bps_samples = deque(maxlen=IP_PROFILE_WINDOW)

    def update(self, pps: float, bps: float) -> None:
        # Add new sample
        self._pps_samples.append(pps)
        self._bps_samples.append(bps)

    def _trend(self, samples: deque) -> float:
        # Positive = rising, negative = falling, 0 = flat
        # Compare second half mean vs first half mean
        n = len(samples)
        if n < 4:
            return 0.0
        mid   = n // 2
        first = sum(list(samples)[:mid]) / mid
        second = sum(list(samples)[mid:]) / (n - mid)
        return second - first

    def _entropy_of_samples(self, samples: deque) -> float:
        # Entropy of the pps values over time
        # Low entropy = repetitive/uniform pattern = attack-like
        # High entropy = varied pattern = more normal
        vals = list(samples)
        if not vals:
            return 0.0
        return _shannon_entropy(vals)

    def verdict(self) -> str:
        # Not enough data yet
        if len(self._pps_samples) < IP_PROFILE_MIN_SAMPLES:
            return "uncertain"

        pps_list    = list(self._pps_samples)
        pps_mean    = sum(pps_list) / len(pps_list)
        pps_trend   = self._trend(self._pps_samples)
        pps_entropy = self._entropy_of_samples(self._pps_samples)

        # Dynamic min samples: extend observation if still uncertain after window
        effective_min = max(IP_PROFILE_MIN_SAMPLES, min(len(pps_list) // 2, 10))
        if len(pps_list) < effective_min:
            return "uncertain"

        # Normalize entropy relative to max possible (log2 of window size)
        max_entropy  = math.log2(len(pps_list)) if len(pps_list) > 1 else 1.0
        norm_entropy = pps_entropy / max_entropy if max_entropy > 0 else 0.0

        # Dynamic std of observed pps — used to scale thresholds
        pps_var = sum((x - pps_mean) ** 2 for x in pps_list) / len(pps_list)
        pps_std = math.sqrt(max(pps_var, 1e-9))
        cv      = pps_std / (abs(pps_mean) + 1e-9)   # coefficient of variation

        # Dynamic repetitive threshold: stable traffic (low cv) → tighten;
        # variable traffic (high cv) → loosen to avoid false attack labels
        repetitive_threshold = max(0.25, min(0.55, 0.4 - cv * 0.15))

        # Dynamic trend threshold: scale with mean pps — large mean needs bigger
        # absolute trend to be significant; small mean is more sensitive
        trend_threshold = max(0.05, min(0.2, 0.1 * (1 + cv)))

        # Rising trend = pps going up over observation window
        rising = pps_trend > (pps_mean * trend_threshold)

        # Uniform/repetitive traffic = low normalized entropy
        repetitive = norm_entropy < repetitive_threshold

        # Declining or stable-low = traffic is slowing down
        declining = pps_trend < -(pps_mean * trend_threshold)
        low_mean  = pps_mean < (sum(list(self._pps_samples)[:3]) / 3 + 1e-9) * 0.5

        # Attack: rising trend AND repetitive pattern
        if rising and repetitive:
            return "attack"

        # Normal: declining or mean is dropping over time
        if declining or low_mean:
            return "normal"

        # Mixed signals
        return "uncertain"


class EntropyAnalyzer:

    def __init__(self):
        self._lock   = threading.Lock()
        self._states: dict[int, _SwitchEntropyState] = {}

        # Per-IP profiles — used during Quarantine + Sinkhole observation
        self._ip_profiles: dict[str, _IpEntropyProfile] = {}

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

        # Dynamic sigma — scales with baseline stability
        attack_sigma = div_base.dynamic_attack_sigma()
        crowd_sigma  = pkt_base.dynamic_crowd_sigma()

        # Dynamic crowd diversity floor — fraction of learned baseline mean
        # Falls back to TEA_MIN_CROWD_DIVERSITY before learning completes
        min_crowd_div = (
            max(TEA_MIN_CROWD_DIVERSITY, div_base.mean * 0.5)
            if div_base.is_learned else TEA_MIN_CROWD_DIVERSITY
        )

        # Attack: diversity collapses AND packet rate collapses (few IPs dominating)
        diversity_collapsed  = div_base.is_low(curr["diversity_entropy"], attack_sigma)
        packetrate_collapsed = pkt_base.is_low(curr["packetrate_entropy"], attack_sigma)
        is_attack_pattern    = diversity_collapsed and packetrate_collapsed

        # Flash crowd: diversity is normal/high + pkt rate is high + diversity not collapsed
        diversity_normal  = not diversity_collapsed
        packetrate_surge  = pkt_base.is_high(curr["packetrate_entropy"], crowd_sigma)
        high_diversity    = curr["diversity_entropy"] >= min_crowd_div
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

        # Low confidence = TEA unsure → let IF decide + feed result back to TEA
        return True

    def confirm_normal(self, dpid: int) -> None:
        """IF confirmed this interval is normal — unlock baseline updates."""
        with self._lock:
            state = self._states.get(dpid)
        if state is None:
            return
        state.div_base.unlock()
        state.pkt_base.unlock()
        state.byt_base.unlock()
        log.debug("TEA [dpid=%d] IF feedback: normal — baseline unlocked", dpid)

    def confirm_attack(self, dpid: int) -> None:
        """IF confirmed this interval is attack — freeze baseline updates."""
        with self._lock:
            state = self._states.get(dpid)
        if state is None:
            return
        state.div_base.lock()
        state.pkt_base.lock()
        state.byt_base.lock()
        log.debug("TEA [dpid=%d] IF feedback: attack — baseline locked", dpid)

    def update_ip(self, src_ip: str, pps: float, bps: float) -> None:
        # Feed one observation interval for this IP
        # Called each tick during Quarantine or Sinkhole observation
        with self._lock:
            if src_ip not in self._ip_profiles:
                self._ip_profiles[src_ip] = _IpEntropyProfile()
            self._ip_profiles[src_ip].update(pps, bps)

    def get_ip_verdict(self, src_ip: str) -> str:
        # Returns "attack", "normal", or "uncertain"
        # Based on pps trend + entropy of that IP's own traffic over time
        with self._lock:
            profile = self._ip_profiles.get(src_ip)
        if profile is None:
            return "uncertain"
        verdict = profile.verdict()
        log.debug("TEA per-IP verdict [%s] → %s", src_ip, verdict)
        return verdict

    def clear_ip(self, src_ip: str) -> None:
        # Remove IP profile on release — frees memory
        with self._lock:
            self._ip_profiles.pop(src_ip, None)
        log.debug("TEA per-IP profile cleared [%s]", src_ip)

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