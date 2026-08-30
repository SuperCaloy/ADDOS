import math
import time
import threading
import numpy as np
from collections import deque
from backend.config import (
    TEA_WINDOW_SIZE,
    TEA_LEARN_INTERVALS,
    TEA_LEARN_MIN_SAMPLES,
    TEA_ATTACK_SIGMA,
    TEA_CROWD_SIGMA,
    TEA_EMA_ALPHA_MIN,
    TEA_EMA_ALPHA_MAX,
    TEA_ROBUST_REJECT_SIGMA,
    TEA_RELEARN_ALPHA,
    TEA_RELEARN_STABLE_INTERVALS,
    TEA_RELEARN_MIN_CONFIDENCE,
    TEA_RELEARN_MAX_IF_ANOMALY_RATE,
    TEA_RELEARN_MAX_CUMULATIVE_DRIFT,
    TEA_RELEARN_BASELINE_DISTANCE_MAX,
    TEA_IDLE_UNLOCK_S,
    TEA_IP_PROFILE_TTL_S,
    TEA_LATCH_MAX_HOLD_S,
    TEA_IF_UNLOCK_STREAK,
    TEA_TEA_LOCK_STREAK,
    TEA_TEA_UNLOCK_STREAK,
    TEA_TEA_HIGH_CONF_LOCK,
    TEA_MIN_FLOWS_PER_INTERVAL,
)

# Read-at-call-time constants (dual-feedback E2 guidance): accessed via the
# config module so runtime/test overrides take effect without reloading.
from backend import config as _cfg

import logging
log = logging.getLogger(__name__)

# Lazy import to avoid circular dependency
def _push_expert_event(payload: dict) -> None:
    try:
        from backend.api.events import push_expert_event as _push
        _push(payload)
    except Exception:
        pass

TEA_VARIANCE_STABLE_THRESHOLD = 0.01
TEA_BASELINE_HISTORY_MAX = 60


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
        # REMOVED: statistically unsound (biased estimator, CLT fails at n=5).
        # Learning now requires full TEA_LEARN_INTERVALS (360 intervals = 180s).
        # Ref: tea-flash-crowd-assessment.md §15, RT1-RT3 findings.
        return False

    def push(self, value: float, force: bool = False,
             max_drift_frac: float | None = None) -> None:
        if not self._learned:
            self._samples.append(value)
            ready = (
                len(self._samples) >= self._learn_n or
                self._variance_stable()
            )
            if ready and len(self._samples) >= TEA_LEARN_MIN_SAMPLES:
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

        if self._locked and not force:
            return

        if force:
            # Supervised relearning: pin the EMA alpha; on the capped path a
            # faster alpha is safe because the drift cap bounds movement.
            self._alpha = TEA_EMA_ALPHA_MIN if max_drift_frac is None else TEA_RELEARN_ALPHA
        else:
            z = abs(value - self._mean) / self._std
            if z >= TEA_ROBUST_REJECT_SIGMA:
                log.debug("TEA robust reject: value=%.4f  z=%.2f >= %.1f", value, z, TEA_ROBUST_REJECT_SIGMA)
                return
            self._alpha    = self._compute_alpha()
        new_mean = self._alpha * value + (1 - self._alpha) * self._mean
        if max_drift_frac is not None and self._mean:
            # REG-1 hardening: supervised relearn must never walk a frozen
            # baseline toward attack scale faster than a fraction of its mean.
            max_step = abs(self._mean) * max_drift_frac
            if abs(new_mean - self._mean) > max_step:
                new_mean = self._mean + (max_step if new_mean > self._mean else -max_step)
        self._mean = new_mean
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
        self.pps_base   = _AdaptiveBaseline(TEA_LEARN_INTERVALS)
        self.last_result = {}

    def observe(self, snapshot: dict) -> None:
        self.window.append(snapshot)

    def learn(self, snapshot: dict, force: bool = False,
              capped: bool = False) -> None:
        self.size_base.push(snapshot["size_var"], force=force,
                            max_drift_frac=_cfg.TEA_RELEARN_MAX_DRIFT_FRAC if capped else None)
        self.intensity_base.push(snapshot["intensity_var"], force=force,
                                 max_drift_frac=_cfg.TEA_RELEARN_MAX_DRIFT_FRAC if capped else None)
        self.proto_base.push(snapshot["proto_entropy"], force=force,
                             max_drift_frac=_cfg.TEA_RELEARN_MAX_DRIFT_FRAC if capped else None)
        self.share_base.push(snapshot["uniform_share"], force=force,
                             max_drift_frac=_cfg.TEA_RELEARN_MAX_DRIFT_FRAC if capped else None)
        if "mean_pps" in snapshot:
            self.pps_base.push(snapshot["mean_pps"], force=force,
                               max_drift_frac=_cfg.TEA_RELEARN_MAX_DRIFT_FRAC if capped else None)

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
            and self.pps_base.is_learned
        )


IP_PROFILE_MIN_SAMPLES = 10
IP_PROFILE_WINDOW      = 40

class _IpEntropyProfile:
    def __init__(self):
        self._pps_samples = deque(maxlen=IP_PROFILE_WINDOW)
        self._bps_samples = deque(maxlen=IP_PROFILE_WINDOW)
        self._last_verdict = "uncertain"
        self._last_update = time.monotonic()

    def update(self, pps: float, bps: float) -> None:
        self._pps_samples.append(pps)
        self._bps_samples.append(bps)
        self._last_update = time.monotonic()

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

        # Dual feedback latch: IF feedback feeds only _if_normal_streak, while
        # TEA verdicts drive the latch via AND-ed hysteresis.
        self._if_normal_streak = 0
        self._tea_normal_streak = 0
        self._tea_attack_streak = 0
        self._attack_latched = False
        self._last_attack_event = time.monotonic()
        self._last_if_anomaly_ts = time.monotonic()
        self._last_tea_eval_seq = -1
        # P2: TEA-side "stable new normal" counter driving supervised
        # relearn without IF confirmation. Deduped per eval interval.
        self._relearn_stable_streak = 0
        # P3: latch age for the bounded max-hold safety valve. The valve also
        # requires TEA silence via _last_moderate_ts (REG-2), not just _last_attack_event.
        self._latch_set_at = time.monotonic()
        self._last_moderate_ts = time.monotonic()
        # P4: per-flow IF anomaly ring buffer for the sustained-rate idle guard.
        self._if_rate_buffer: deque = deque(maxlen=_cfg.TEA_IF_RATE_WINDOW)

        self._flow_buffer = deque(maxlen=2000)
        self._last_eval_time = 0.0
        self._eval_interval = 0.5
        self._eval_seq = 0

    @property
    def fb_normal_streak(self) -> int:
        with self._lock:
            return self._if_normal_streak

    @property
    def if_normal_streak(self) -> int:
        with self._lock:
            return self._if_normal_streak

    @property
    def tea_normal_streak(self) -> int:
        with self._lock:
            return self._tea_normal_streak

    @property
    def attack_latched(self) -> bool:
        with self._lock:
            return self._attack_latched

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
                and self._global_state.pps_base.locked
            )

    def update(self, dpid: int, flows: list[dict]) -> dict:
        with self._lock:
            now = time.monotonic()
            self._flow_buffer.extend(flows)

            if now - self._last_eval_time < self._eval_interval and self._global_state.last_result:
                return self._global_state.last_result

            self._last_eval_time = now
            self._eval_seq += 1
            current_flows = list(self._flow_buffer)
            self._flow_buffer.clear()

        if not current_flows:
            # Idle gap: preserve the previous result verbatim rather than
            # overwriting it with a neutral learned=False verdict.
            prev = self._global_state.last_result
            if prev:
                res = dict(prev)
                res["idle"] = True
                return res
            return self._neutral(0.0, 0.0, learned=False)

        eps = 1e-9
        sizes = []
        intensities = []
        ppss = []
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
            ppss.append(max(pps, 0.0))

            proto = f.get("ip_proto", 0)
            protos[proto] = protos.get(proto, 0) + 1

        size_var = float(np.var(sizes)) if sizes else 0.0
        intensity_var = float(np.var(intensities)) if intensities else 0.0
        proto_entropy = _shannon_entropy(list(protos.values()))
        mean_pps = sum(ppss) / len(ppss) if ppss else 0.0

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
            "mean_pps": mean_pps,
        }

        with self._lock:
            state = self._global_state
            state.observe(snapshot)

            is_learned = state.is_learned
            size_base   = state.size_base
            intensity_base   = state.intensity_base
            proto_base   = state.proto_base
            share_base   = state.share_base
            pps_base     = state.pps_base

            if not state.is_ready():
                state.learn(snapshot)
                res = self._neutral(size_var, intensity_var, learned=False)
                res["eval_seq"] = self._eval_seq
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
                pps_surge = False
                pps_z = 0.0
                proto_surge = False
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
                # P1: uniformity at sigma 2.0 with an absolute share floor,
                # so only strongly-uniform traffic is even considered.
                mechanized_cluster = (
                    share_base.is_high(curr["uniform_share"], _cfg.TEA_UNIFORM_SHARE_SIGMA)
                    and curr["uniform_share"] >= _cfg.TEA_MECHANIZED_MIN_UNIFORM_SHARE
                )
                proto_surge = proto_base.is_high(curr["proto_entropy"], _cfg.TEA_UNIFORM_SHARE_SIGMA)
                # P1 volume companion: absolute pps vs the learned normal baseline.
                pps_z = pps_base.z_score(curr["mean_pps"])
                pps_surge = pps_base.is_high(curr["mean_pps"], _cfg.TEA_PPS_SURGE_SIGMA)

        size_delta  = curr["size_var"]  - prev["size_var"]
        intensity_delta = curr["intensity_var"] - prev["intensity_var"]

        if not is_learned:
            log.debug("TEA global learning phase")
            with self._lock:
                state.learn(snapshot)
            res = self._neutral(size_var, intensity_var, learned=False)
            res["eval_seq"] = self._eval_seq
            with self._lock:
                state.last_result = res
            return res

        # Degenerate-interval guard: too few flows yield meaningless aggregate
        # stats (e.g. false "mechanized cluster"); suppress the verdict.
        degenerate = len(current_flows) < TEA_MIN_FLOWS_PER_INTERVAL
        is_flash_crowd = False
        confidence = "low"
        # P1: uniformity-only signals count as attack only with an attack-scale
        # volume companion. R1 backstops very high multi-source uniformity.
        volume_anomaly = size_surge or intensity_surge or pps_surge
        collapse_anomaly = size_collapsed or intensity_collapsed or proto_collapsed
        uniform_backstop = (
            mechanized_cluster
            and curr["uniform_share"] >= _cfg.TEA_UNIFORM_BACKSTOP_SHARE
            and curr["unique_ips"] >= _cfg.TEA_UNIFORM_BACKSTOP_MIN_IPS
        )
        is_attack_pattern = (
            size_surge or intensity_surge or pps_surge
            or ((collapse_anomaly or mechanized_cluster) and volume_anomaly)
            or uniform_backstop
        ) if not degenerate else False

        if is_attack_pattern:
            if uniform_backstop and not volume_anomaly:
                confidence = "moderate"  # many-source uniform flood, no volume surge
            elif ((size_collapsed or size_surge) and (intensity_collapsed or intensity_surge)) or (
                mechanized_cluster and (
                    size_collapsed or size_surge or intensity_collapsed
                    or intensity_surge or proto_collapsed or proto_surge
                    or pps_surge
                )
            ):
                confidence = "high"  # Multi-dimension confirmation
            else:
                confidence = "moderate"  # Single dimension fired

        # Supervised relearning (P2): a stable TEA-side "new normal" force-learns
        # the frozen baselines without IF confirmation (REG-1 caps drift and excludes
        # high-confidence snapshots so attack-scale data can't poison baselines).
        # Contamination guard: require moderate confidence + low IF anomaly rate.
        if not degenerate:
            with self._lock:
                if_anomaly_rate = self._if_anomaly_rate()
                supervised = (
                    self._attack_latched
                    and self._relearn_stable_streak >= TEA_RELEARN_STABLE_INTERVALS
                    and confidence == TEA_RELEARN_MIN_CONFIDENCE
                    and if_anomaly_rate < TEA_RELEARN_MAX_IF_ANOMALY_RATE
                )
            if not is_attack_pattern or supervised:
                with self._lock:
                    state.learn(snapshot, force=supervised, capped=supervised)

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
            "mean_pps":  round(curr["mean_pps"], 4),
            "pps_zscore":    round(pps_z, 4),
            "pps_baseline":  round(pps_base.mean, 4),
            "mechanized_cluster":    mechanized_cluster,
            "size_surge":    size_surge,
            "intensity_surge":   intensity_surge,
            "pps_surge":     pps_surge,
            "uniform_backstop":  uniform_backstop,
            "baseline_mean_size":  round(size_base.mean, 4),
            "baseline_mean_intensity":  round(intensity_base.mean, 4),
            "unique_ips":         curr["unique_ips"],
            "is_attack_pattern":  is_attack_pattern,
            "is_flash_crowd":     is_flash_crowd,
            "is_learned":         True,
            "confidence":         confidence,
            "eval_seq":           self._eval_seq,
        }
        if degenerate:
            result["degenerate_interval"] = True

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
                "_attack_latched": self.attack_latched,
                "_fb_normal_streak": self.fb_normal_streak,
                "_tea_normal_streak": self.tea_normal_streak,
                "eval_seq": self._eval_seq,
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

    def _lock_all(self) -> None:
        self._global_state.size_base.lock()
        self._global_state.intensity_base.lock()
        self._global_state.proto_base.lock()
        self._global_state.share_base.lock()
        self._global_state.pps_base.lock()

    def _unlock_all(self) -> None:
        self._global_state.size_base.unlock()
        self._global_state.intensity_base.unlock()
        self._global_state.proto_base.unlock()
        self._global_state.share_base.unlock()
        self._global_state.pps_base.unlock()

    def _set_latch(self, latched: bool, reason: str, caller_holds_lock: bool = False) -> None:
        if not caller_holds_lock:
            with self._lock:
                return self._set_latch(latched, reason, caller_holds_lock=True)
        if self._attack_latched == latched:
            return
        self._attack_latched = latched
        if latched:
            self._latch_set_at = time.monotonic()
            self._lock_all()
            log.info("TEA latch LOCKED (%s): tea_attack_streak=%d", reason, self._tea_attack_streak)
        else:
            self._unlock_all()
            log.info("TEA latch UNLOCKED (%s): if_streak=%d tea_normal_streak=%d",
                     reason, self._if_normal_streak, self._tea_normal_streak)

    def _try_unlock(self) -> None:
        # AND logic: both channels must independently agree traffic is normal.
        # (RLock held by caller.)
        if (
            self._if_normal_streak >= TEA_IF_UNLOCK_STREAK
            and self._tea_normal_streak >= TEA_TEA_UNLOCK_STREAK
        ):
            self._set_latch(False, "both streaks satisfied", caller_holds_lock=True)

    def _if_sustained_anomaly(self, now: float) -> bool:
        """P4: IF is 'sustained anomalous' only when anomalies dominate the
        recent per-flow window AND the timestamp is still fresh. A single
        sporadic false positive never blocks recovery."""
        if now - self._last_if_anomaly_ts >= TEA_IDLE_UNLOCK_S:
            return False
        buf = self._if_rate_buffer
        if not buf:
            return False
        return (sum(buf) / len(buf)) >= _cfg.TEA_IF_ANOMALY_RATE_BLOCK

    def _if_anomaly_rate(self) -> float:
        """Return the current IF anomaly rate (0.0-1.0) from the ring buffer."""
        buf = self._if_rate_buffer
        if not buf:
            return 0.0
        return sum(buf) / len(buf)

    def feedback_if(self, is_anomaly: bool) -> None:
        """Per-flow IF feedback. Streak-only: NEVER locks baselines.

        Isolated anomalies halve the streak (decay) instead of zeroing it,
        so occasional IF false positives delay rather than restart recovery.
        Every call feeds the sustained-rate ring buffer used by idle_tick.
        """
        with self._lock:
            self._if_rate_buffer.append(1 if is_anomaly else 0)
            if is_anomaly:
                self._if_normal_streak //= 2
                self._last_if_anomaly_ts = time.monotonic()
                return
            self._if_normal_streak += 1
            self._try_unlock()

    def feedback_tea(self, is_attack: bool, confidence: str = "low",
                     eval_seq: int | None = None) -> None:
        """Per-eval-interval TEA verdict feedback driving the latch.

        eval_seq dedup guarantees one count per interval even when many
        flows carry the same cached result.
        """
        with self._lock:
            if eval_seq is not None:
                # P6: telemetry-provided seq is attacker-influenceable.
                # Reject non-int / negative values and absurd forward jumps
                # that would dedup-blackout every later interval.
                if isinstance(eval_seq, bool) or not isinstance(eval_seq, int):
                    return
                if eval_seq < 0:
                    return
                if eval_seq - self._last_tea_eval_seq > _cfg.TEA_EVAL_SEQ_MAX_JUMP:
                    return
                if eval_seq <= self._last_tea_eval_seq:
                    return
                self._last_tea_eval_seq = eval_seq

            # RT-1 ordering: the seq is recorded even when we bail; a moderate
            # latched verdict is treated as frozen-baseline noise (P2 halts relearn, REG-1).
            if self._attack_latched and is_attack and confidence != "high":
                # P2 stable-moderate trigger: inert latched moderates are the
                # frozen-baseline FP signature that builds the stability counter.
                self._relearn_stable_streak += 1
                self._last_moderate_ts = time.monotonic()
                return

            if is_attack or confidence == "high":
                if not is_attack and confidence == "high":
                    is_attack = True
                self._tea_normal_streak = 0
                self._relearn_stable_streak = 0
                self._last_attack_event = time.monotonic()
                if TEA_TEA_HIGH_CONF_LOCK and confidence == "high":
                    self._set_latch(True, "high confidence attack", caller_holds_lock=True)
                    return
                self._tea_attack_streak += 1
                if self._tea_attack_streak >= TEA_TEA_LOCK_STREAK:
                    self._set_latch(True, "sustained attack intervals", caller_holds_lock=True)
                return

            self._tea_attack_streak = 0
            self._tea_normal_streak += 1
            if self._attack_latched:
                self._relearn_stable_streak += 1
            self._try_unlock()

    def idle_tick(self, now: float | None = None) -> None:
        """Zero-traffic recovery path: no flow feedback arrives during
        silence, so unlock is time-based on the last observed attack signal.

        P4: the IF guard is a sustained anomaly-rate window, not a single
        timestamp, so sporadic IF false positives no longer block recovery.
        P3: a bounded max-hold valve force-unlocks a latch that has outlived
        TEA_LATCH_MAX_HOLD_S while TEA itself reports sustained silence
        (normal-verdict streak, not merely "no high-conf event", per REG-2).
        """
        now = now if now is not None else time.monotonic()
        with self._lock:
            if not self._attack_latched:
                return
            if (
                now - self._last_attack_event >= TEA_IDLE_UNLOCK_S
                and not self._if_sustained_anomaly(now)
            ):
                self._if_normal_streak = 0
                self._tea_normal_streak = 0
                self._relearn_stable_streak = 0
                self._set_latch(False, "idle timeout (no attack signal)", caller_holds_lock=True)
                return
            if (
                now - self._latch_set_at >= TEA_LATCH_MAX_HOLD_S
                and self._tea_normal_streak >= TEA_TEA_UNLOCK_STREAK
                and now - self._last_attack_event >= _cfg.TEA_LATCH_HOLD_IF_GRACE_S
                and now - self._last_moderate_ts >= _cfg.TEA_LATCH_HOLD_IF_GRACE_S
            ):
                # Sustained TEA silence + hold bound exceeded: re-anchor the
                # baselines once (drift-capped) and release the latch.
                if self._global_state.window:
                    self._global_state.learn(
                        self._global_state.latest(), force=True, capped=True
                    )
                self._set_latch(False, "max-hold exceeded", caller_holds_lock=True)

    def telemetry(self) -> dict:
        """P5: recovery observability for the expert endpoint and
        acceptance tests asserting the hold bound."""
        with self._lock:
            now = time.monotonic()
            buf = self._if_rate_buffer
            return {
                "attack_latched": self._attack_latched,
                "latch_age_s": round(now - self._latch_set_at, 3),
                "last_attack_age_s": round(now - self._last_attack_event, 3),
                "last_if_anomaly_age_s": round(now - self._last_if_anomaly_ts, 3),
                "if_anomaly_rate": round(sum(buf) / len(buf), 4) if buf else 0.0,
                "relearn_stable_streak": self._relearn_stable_streak,
            }

    def mean_size_baseline(self) -> float:
        """Lock-safe read of the size baseline mean for the dynamic low-rate gate."""
        with self._lock:
            return self._global_state.size_base.mean

    def cleanup_stale_profiles(self, max_age_s: float = TEA_IP_PROFILE_TTL_S,
                               now: float | None = None) -> int:
        """Drop per-IP profiles untouched longer than max_age_s."""
        now = now if now is not None else time.monotonic()
        cutoff = now - max_age_s
        removed = 0
        with self._lock:
            stale = [ip for ip, p in self._ip_profiles.items() if p._last_update < cutoff]
            for ip in stale:
                del self._ip_profiles[ip]
                removed += 1
        return removed

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
            "mean_pps":  0.0,
            "pps_zscore":    0.0,
            "pps_baseline":  0.0,
            "mechanized_cluster":    False,
            "size_surge":    False,
            "intensity_surge":   False,
            "pps_surge":     False,
            "uniform_backstop":  False,
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
