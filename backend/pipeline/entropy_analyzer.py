import math
import time
import threading
import numpy as np
from collections import deque
from backend.config import TEA_WINDOW_SIZE

import logging
log = logging.getLogger(__name__)

# Lazy import to avoid circular dependency
def _push_expert_event(payload: dict) -> None:
    try:
        from backend.api.events import push_expert_event as _push
        _push(payload)
    except Exception:
        pass

# === ADAPTIVE TEA CONSTANTS ===
TEA_LEARN_INTERVALS   = 15
TEA_ATTACK_SIGMA      = 2.5
TEA_CROWD_SIGMA       = 1.5
TEA_MIN_CROWD_DIVERSITY = 1.0
TEA_EMA_ALPHA_MIN     = 0.02
TEA_EMA_ALPHA_MAX     = 0.10
TEA_VARIANCE_STABLE_THRESHOLD = 0.01
TEA_ROBUST_REJECT_SIGMA = 3.0
TEA_FEEDBACK_UNLOCK_STREAK = 10
TEA_BASELINE_HISTORY_MAX = 60
TEA_UNIFORM_SHARE_SIGMA = TEA_CROWD_SIGMA


def _shannon_entropy(values: list[float]) -> float:
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
    def __init__(self, learn_intervals: int):
        self._learn_n      = learn_intervals
        self._samples      = []
        self._mean         = None
        self._variance     = None
        self._learned      = False
        self._alpha        = TEA_EMA_ALPHA_MIN
        self._locked        = False
        self._baseline_history = []

    @property
    def is_learned(self) -> bool:
        return self._learned

    def _compute_alpha(self) -> float:
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_EMA_ALPHA_MIN
        cv = math.sqrt(max(self._variance, 1e-9)) / (abs(self._mean) + 1e-9)
        alpha = TEA_EMA_ALPHA_MAX - cv * (TEA_EMA_ALPHA_MAX - TEA_EMA_ALPHA_MIN)
        return max(TEA_EMA_ALPHA_MIN, min(TEA_EMA_ALPHA_MAX, alpha))

    def _variance_stable(self) -> bool:
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
                self._baseline_history.append(self._mean)
                log.info(
                    "TEA baseline learned - mean=%.4f  std=%.4f  alpha=%.4f  (n=%d samples)",
                    self._mean, self._std, self._alpha, len(self._samples)
                )
            return

        if self._locked:
            return

        z = abs(value - self._mean) / self._std
        if z >= TEA_ROBUST_REJECT_SIGMA:
            log.debug("TEA robust reject: value=%.4f  z=%.2f >= %.1f", value, z, TEA_ROBUST_REJECT_SIGMA)
            return

        self._alpha    = self._compute_alpha()
        self._mean     = self._alpha * value + (1 - self._alpha) * self._mean
        err            = (value - self._mean) ** 2
        self._variance = self._alpha * err + (1 - self._alpha) * self._variance
        self._baseline_history.append(self._mean)
        if len(self._baseline_history) > TEA_BASELINE_HISTORY_MAX:
            self._baseline_history.pop(0)

    def lock(self) -> None:
        self._locked = True

    def unlock(self) -> None:
        self._locked = False

    @property
    def mean(self) -> float:
        return self._mean if self._mean is not None else 0.0

    @property
    def _std(self) -> float:
        return math.sqrt(max(self._variance, 1e-9)) if self._variance is not None else 1.0

    def dynamic_attack_sigma(self) -> float:
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_ATTACK_SIGMA
        cv = self._std / (abs(self._mean) + 1e-9)
        sigma = TEA_ATTACK_SIGMA + cv * 1.5
        return max(2.0, min(2.8, sigma))

    def dynamic_crowd_sigma(self) -> float:
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_CROWD_SIGMA
        cv = self._std / (abs(self._mean) + 1e-9)
        sigma = TEA_CROWD_SIGMA + cv * 1.0
        return max(1.2, min(2.0, sigma))

    def z_score(self, value: float) -> float:
        if not self._learned:
            return 0.0
        return (value - self._mean) / self._std

    def is_low(self, value: float, sigma: float) -> bool:
        return self._learned and self.z_score(value) <= -sigma

    def is_high(self, value: float, sigma: float) -> bool:
        return self._learned and self.z_score(value) >= sigma

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def alpha(self) -> float:
        return self._alpha

    @property
    def baseline_history(self) -> list[float]:
        return list(self._baseline_history)


class _GlobalEntropyState:
    def __init__(self, window_size: int):
        self.window    = deque(maxlen=window_size)
        self.size_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.intensity_base  = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.proto_base = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.share_base = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.last_result = {}

    def observe(self, snapshot: dict) -> None:
        self.window.append(snapshot)

    def learn(self, snapshot: dict) -> None:
        self.size_base.push(snapshot["size_var"])
        self.intensity_base.push(snapshot["intensity_var"])
        self.proto_base.push(snapshot["proto_entropy"])
        self.share_base.push(snapshot["uniform_share"])

    def push(self, snapshot: dict) -> None:
        self.observe(snapshot)
        self.learn(snapshot)

    def is_ready(self) -> bool:
        return len(self.window) >= 2

    def latest(self) -> dict:
        return self.window[-1]

    def previous(self) -> dict:
        return self.window[-2]

    @property
    def is_learned(self) -> bool:
        return (
            self.size_base.is_learned
            and self.intensity_base.is_learned
            and self.proto_base.is_learned
            and self.share_base.is_learned
        )


IP_PROFILE_MIN_SAMPLES = 5
IP_PROFILE_WINDOW      = 20

class _IpEntropyProfile:
    def __init__(self):
        self._pps_samples = deque(maxlen=IP_PROFILE_WINDOW)
        self._bps_samples = deque(maxlen=IP_PROFILE_WINDOW)
        self._last_verdict = "uncertain"

    def update(self, pps: float, bps: float) -> None:
        self._pps_samples.append(pps)
        self._bps_samples.append(bps)

    def _trend(self, samples: deque) -> float:
        n = len(samples)
        if n < 4:
            return 0.0
        mid   = n // 2
        first = sum(list(samples)[:mid]) / mid
        second = sum(list(samples)[mid:]) / (n - mid)
        return second - first

    def _entropy_of_samples(self, samples: deque) -> float:
        vals = list(samples)
        if not vals:
            return 0.0
        return _shannon_entropy(vals)

    def verdict(self) -> str:
        """
        Evaluate traffic profile for a specific IP.
        
        Note: The per-IP verdict relies on fine-grained trend/entropy analysis
        over a short sliding window, whereas the global gate (is_attack_pattern) 
        relies on aggregate variance collapse across all traffic. They are kept
        separate because the global gate detects the onset of a large attack, 
        while this method tracks individual IP behavior.
        """
        if len(self._pps_samples) < IP_PROFILE_MIN_SAMPLES:
            return "uncertain"

        pps_list    = list(self._pps_samples)
        pps_mean    = sum(pps_list) / len(pps_list)
        pps_trend   = self._trend(self._pps_samples)
        pps_entropy = self._entropy_of_samples(self._pps_samples)

        effective_min = max(IP_PROFILE_MIN_SAMPLES, min(len(pps_list) // 2, 10))
        if len(pps_list) < effective_min:
            return "uncertain"

        max_entropy  = math.log2(len(pps_list)) if len(pps_list) > 1 else 1.0
        norm_entropy = pps_entropy / max_entropy if max_entropy > 0 else 0.0

        pps_var = sum((x - pps_mean) ** 2 for x in pps_list) / len(pps_list)
        pps_std = math.sqrt(max(pps_var, 1e-9))
        cv      = pps_std / (abs(pps_mean) + 1e-9)

        repetitive_threshold = max(0.25, min(0.55, 0.4 - cv * 0.15))
        trend_threshold = max(0.05, min(0.2, 0.1 * (1 + cv)))

        rising = pps_trend > (pps_mean * trend_threshold)
        repetitive = norm_entropy < repetitive_threshold
        declining = pps_trend < -(pps_mean * trend_threshold)
        low_mean  = pps_mean < (sum(list(self._pps_samples)[:3]) / 3 + 1e-9) * 0.5

        if rising and repetitive:
            self._last_verdict = "attack"
            return "attack"

        if rising or repetitive:
            self._last_verdict = "attack"
            return "attack"

        if declining or low_mean:
            self._last_verdict = "normal"
            return "normal"

        if self._last_verdict == "attack" and repetitive:
            return "attack"

        self._last_verdict = "uncertain"
        return "uncertain"


class EntropyAnalyzer:

    def __init__(self):
        self._lock   = threading.RLock()
        self._global_state = _GlobalEntropyState(TEA_WINDOW_SIZE)
        self._ip_profiles: dict[str, _IpEntropyProfile] = {}
        self._fb_normal_streak = 0
        self._would_block_count = 0
        
        self._flow_buffer = deque(maxlen=2000)
        self._last_eval_time = 0.0
        self._eval_interval = 0.5

    @property
    def fb_normal_streak(self) -> int:
        with self._lock:
            return self._fb_normal_streak

    @property
    def would_block_count(self) -> int:
        with self._lock:
            return self._would_block_count

    @property
    def is_locked(self) -> bool:
        with self._lock:
            return (
                self._global_state.size_base.locked
                and self._global_state.intensity_base.locked
                and self._global_state.proto_base.locked
                and self._global_state.share_base.locked
            )

    def update(self, dpid: int, flows: list[dict]) -> dict:
        with self._lock:
            now = time.time()
            self._flow_buffer.extend(flows)
            
            if now - self._last_eval_time < self._eval_interval and self._global_state.last_result:
                return self._global_state.last_result
            
            self._last_eval_time = now
            current_flows = list(self._flow_buffer)
            self._flow_buffer.clear()

        if not current_flows:
            res = self._neutral(0.0, 0.0, learned=False)
            with self._lock:
                self._global_state.last_result = res
            return res

        eps = 1e-9
        sizes = []
        intensities = []
        protos = {}
        unique_ips = set()
        
        for f in current_flows:
            src = f.get("src_ip", "")
            if src and src != "0.0.0.0":
                unique_ips.add(src)
            
            pkt = float(f.get("packet_count", 0))
            byt = float(f.get("byte_count", 0))
            pps = float(f.get("packet_count_per_second", 0))
            bps = float(f.get("byte_count_per_second", 0))
            
            avg_bytes_per_pkt = byt / (pkt + eps)
            pkt_size_uniformity = math.log1p(max(avg_bytes_per_pkt, 0))
            flow_intensity = math.log1p(max(pps * bps, 0))
            
            sizes.append(pkt_size_uniformity)
            intensities.append(flow_intensity)
            
            proto = f.get("ip_proto", 0)
            protos[proto] = protos.get(proto, 0) + 1

        size_var = float(np.var(sizes)) if sizes else 0.0
        intensity_var = float(np.var(intensities)) if intensities else 0.0
        proto_entropy = _shannon_entropy(list(protos.values()))

        if sizes:
            med_size  = float(np.median(sizes))
            med_int   = float(np.median(intensities))
            mad_size  = float(np.median(np.abs(np.array(sizes) - med_size)))
            mad_int   = float(np.median(np.abs(np.array(intensities) - med_int)))
            tol_size  = max(0.02, 3.0 * mad_size)
            tol_int   = max(0.10, 3.0 * mad_int)
            uniform_n = sum(
                1 for s, i in zip(sizes, intensities)
                if abs(s - med_size) <= tol_size and abs(i - med_int) <= tol_int
            )
            uniform_share = uniform_n / len(sizes)
        else:
            uniform_share = 0.0

        snapshot = {
            "size_var":  size_var,
            "intensity_var": intensity_var,
            "proto_entropy": proto_entropy,
            "uniform_share": uniform_share,
            "unique_ips": len(unique_ips),
        }

        with self._lock:
            state = self._global_state
            state.observe(snapshot)

            is_learned = state.is_learned
            size_base   = state.size_base
            intensity_base   = state.intensity_base
            proto_base   = state.proto_base
            share_base   = state.share_base

            if not state.is_ready():
                state.learn(snapshot)
                res = self._neutral(size_var, intensity_var, learned=False)
                state.last_result = res
                return res

            curr = state.latest()
            prev = state.previous()

            if not is_learned:
                size_z  = 0.0
                intensity_z  = 0.0
                attack_sigma = TEA_ATTACK_SIGMA
                size_collapsed  = False
                intensity_collapsed = False
                size_surge = False
                intensity_surge = False
                mechanized_cluster = False
            else:
                size_z  = size_base.z_score(curr["size_var"])
                intensity_z  = intensity_base.z_score(curr["intensity_var"])
                proto_z = proto_base.z_score(curr["proto_entropy"])
                attack_sigma = size_base.dynamic_attack_sigma()
                size_collapsed  = size_base.is_low(curr["size_var"], attack_sigma)
                intensity_collapsed = intensity_base.is_low(curr["intensity_var"], attack_sigma)
                proto_collapsed = proto_base.is_low(curr["proto_entropy"], attack_sigma)  # protocol concentration lowers entropy
                size_surge = size_base.is_high(curr["size_var"], attack_sigma)
                intensity_surge = intensity_base.is_high(curr["intensity_var"], attack_sigma)
                share_z = share_base.z_score(curr["uniform_share"])
                mechanized_cluster = share_base.is_high(curr["uniform_share"], TEA_UNIFORM_SHARE_SIGMA)
                proto_surge = proto_base.is_high(curr["proto_entropy"], TEA_UNIFORM_SHARE_SIGMA)

        size_delta  = curr["size_var"]  - prev["size_var"]
        intensity_delta = curr["intensity_var"] - prev["intensity_var"]

        if not is_learned:
            log.debug("TEA global learning phase")
            with self._lock:
                state.learn(snapshot)
            res = self._neutral(size_var, intensity_var, learned=False)
            with self._lock:
                state.last_result = res
            return res

        is_attack_pattern = (
            mechanized_cluster or proto_surge or proto_collapsed
            or size_collapsed or intensity_collapsed
            or size_surge or intensity_surge
        )
        is_flash_crowd    = False

        if is_attack_pattern:
            if ((size_collapsed or size_surge) and (intensity_collapsed or intensity_surge)) or (
                mechanized_cluster and (
                    size_collapsed or size_surge or intensity_collapsed
                    or intensity_surge or proto_collapsed or proto_surge
                )
            ):
                confidence = "high"  # Multi-dimension confirmation
            else:
                confidence = "moderate"  # Single dimension fired
        else:
            confidence = "low"

        if not is_attack_pattern:
            with self._lock:
                state.learn(snapshot)

        result = {
            "size_var":  round(curr["size_var"],  4),
            "intensity_var": round(curr["intensity_var"], 4),
            "proto_entropy": round(curr["proto_entropy"], 4),
            "size_delta":    round(size_delta,  4),
            "intensity_delta":   round(intensity_delta, 4),
            "size_zscore":   round(size_z,  4),
            "intensity_zscore":  round(intensity_z,  4),
            "proto_zscore":  round(proto_z, 4),
            "uniform_share": round(curr["uniform_share"], 4),
            "uniform_share_zscore":  round(share_z, 4),
            "mechanized_cluster":    mechanized_cluster,
            "size_surge":    size_surge,
            "intensity_surge":   intensity_surge,
            "baseline_mean_size":  round(size_base.mean, 4),
            "baseline_mean_intensity":  round(intensity_base.mean, 4),
            "unique_ips":         curr["unique_ips"],
            "is_attack_pattern":  is_attack_pattern,
            "is_flash_crowd":     is_flash_crowd,
            "is_learned":         True,
            "confidence":         confidence,
        }

        if is_attack_pattern:
            log.info("TEA global attack pattern - size_z=%.2f  int_z=%.2f  conf=%s", size_z, intensity_z, confidence)

        _push_expert_event({
            "tea_update": {
                "dpid": 0,
                "size_var": result["size_var"],
                "intensity_var": result["intensity_var"],
                "proto_entropy": result["proto_entropy"],
                "size_z": result["size_zscore"],
                "intensity_z": result["intensity_zscore"],
                "proto_z": result["proto_zscore"],
                "uniform_share": result["uniform_share"],
                "mechanized_cluster": mechanized_cluster,
                "unique_ips": result["unique_ips"],
                "is_attack": is_attack_pattern,
                "is_flash_crowd": is_flash_crowd,
                "is_learned": True,
                "confidence": confidence,
                "_locked": self.is_locked,
                "_fb_normal_streak": self.fb_normal_streak,
            }
        })

        with self._lock:
            state.last_result = result
        return result

    def should_submit(self, tea_result: dict, is_flood_prefilter_flagged: bool) -> bool:
        would_block = (
            not is_flood_prefilter_flagged
            and tea_result.get("is_learned", False)
            and not tea_result.get("is_attack_pattern", False)
            and tea_result.get("confidence", "low") == "low"
        )
        if would_block:
            with self._lock:
                self._would_block_count += 1
            log.info("TEA gate advisory: would have blocked (total=%d)", self._would_block_count)
        return True

    def confirm_normal(self, dpid: int = 0) -> None:
        with self._lock:
            self._global_state.size_base.unlock()
            self._global_state.intensity_base.unlock()
            self._global_state.proto_base.unlock()
            self._global_state.share_base.unlock()

    def confirm_attack(self, dpid: int = 0) -> None:
        with self._lock:
            self._global_state.size_base.lock()
            self._global_state.intensity_base.lock()
            self._global_state.proto_base.lock()
            self._global_state.share_base.lock()

    def feedback(self, is_anomaly: bool) -> None:
        with self._lock:
            if is_anomaly:
                self._fb_normal_streak = 0
                self._global_state.size_base.lock()
                self._global_state.intensity_base.lock()
                self._global_state.proto_base.lock()
                self._global_state.share_base.lock()
                return
            self._fb_normal_streak += 1
            if self._fb_normal_streak >= TEA_FEEDBACK_UNLOCK_STREAK:
                self._fb_normal_streak = 0
                self._global_state.size_base.unlock()
                self._global_state.intensity_base.unlock()
                self._global_state.proto_base.unlock()
                self._global_state.share_base.unlock()

    def update_ip(self, src_ip: str, pps: float, bps: float) -> None:
        with self._lock:
            if src_ip not in self._ip_profiles:
                self._ip_profiles[src_ip] = _IpEntropyProfile()
            self._ip_profiles[src_ip].update(pps, bps)

    def get_ip_verdict(self, src_ip: str) -> str:
        with self._lock:
            profile = self._ip_profiles.get(src_ip)
        if profile is None:
            return "uncertain"
        return profile.verdict()

    def clear_ip(self, src_ip: str) -> None:
        with self._lock:
            self._ip_profiles.pop(src_ip, None)

    def reset_switch(self, dpid: int) -> None:
        # Compatibility, reset global instead
        with self._lock:
            self._global_state = _GlobalEntropyState(TEA_WINDOW_SIZE)

    def _neutral(self, size: float, intensity: float, learned: bool = False) -> dict:
        return {
            "size_var":  round(size, 4),
            "intensity_var": round(intensity, 4),
            "proto_entropy": 0.0,
            "size_delta":    0.0,
            "intensity_delta":   0.0,
            "size_zscore":   0.0,
            "intensity_zscore":  0.0,
            "proto_zscore":  0.0,
            "uniform_share": 0.0,
            "uniform_share_zscore":  0.0,
            "mechanized_cluster":    False,
            "size_surge":    False,
            "intensity_surge":   False,
            "baseline_mean_size":  0.0,
            "baseline_mean_intensity":  0.0,
            "unique_ips":         0,
            "is_attack_pattern":  False,
            "is_flash_crowd":     False,
            "is_learned":         learned,
            "confidence":         "low",
        }

# Module-level singleton
entropy_analyzer = EntropyAnalyzer()
