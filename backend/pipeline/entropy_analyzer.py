import math
import time
import threading
import numpy as np
from collections import deque
from backend.config import (
    TEA_WINDOW_SIZE,
    TEA_LEARN_MIN_SAMPLES,
    TEA_LEARN_MIN_MEAN_PPS,
    TEA_WARMUP_REJECT_FACTOR,
    TEA_EXTREME_Z_SIGMA,
    TEA_EXTREME_Z_RESTART_INTERVALS,
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
    TEA_SHADOW_ENABLED,
    TEA_SHADOW_MIN_SAMPLES,
    TEA_SHADOW_MAX_AGE_S,
    TEA_TEMPORAL_ENTROPY_BINS,
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
# Warmup provisional rejection: after this many accepted samples each baseline
# holds a provisional mean and rejects outlier warmup samples (multiplicative
# factor from config). PPS uses an additional absolute dynamic cap; other
# baselines use relative-ratio rejection plus optional min_learn_value floors.
TEA_WARMUP_REJECT_AFTER = 30


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
    def __init__(self, learn_samples: int, warmup_guard: bool = False,
                 min_learn_mean: float | None = None,
                 min_learn_value: float | None = None):
        self._learn_n      = learn_samples
        self._samples      = []
        self._mean         = None
        self._variance     = None
        self._learned      = False
        self._alpha        = TEA_EMA_ALPHA_MIN
        self._locked       = False
        self._baseline_history = []
        # Learning window: wall-clock anchor set at the first warmup sample.
        self._learn_started_at: float | None = None
        # Warmup guard: reject attack-scale samples during learning.
        # All baselines get the dynamic cap; PPS also gets a relative ratio
        # guard via min_learn_mean. Non-PPS baselines can optionally use
        # min_learn_value to reject collapsed values during learning.
        self._warmup_guard = warmup_guard
        # Validity gate (pps only): refuse to finalize below this mean.
        self._min_learn_mean = min_learn_mean
        # Minimum value gate: reject samples below this during learning (e.g.
        # size_var/intensity_var collapse during attack yields near-zero values).
        self._min_learn_value = min_learn_value
        # Provisional running sum for the warmup guard.
        self._psum = 0.0

    @property
    def is_learned(self) -> bool:
        return self._learned

    def _compute_alpha(self) -> float:
        if self._variance is None or self._mean is None or self._mean == 0:
            return TEA_EMA_ALPHA_MIN
        cv = math.sqrt(max(self._variance, 1e-9)) / (abs(self._mean) + 1e-9)
        alpha = TEA_EMA_ALPHA_MAX - cv * (TEA_EMA_ALPHA_MAX - TEA_EMA_ALPHA_MIN)
        return max(TEA_EMA_ALPHA_MIN, min(TEA_EMA_ALPHA_MAX, alpha))

    def _warmup_reject(self, value: float) -> bool:
        """Provisional guard during the learning phase.

        Three rules (applied in order):
        - min_learn_value: reject values below this floor (e.g. size_var /
          intensity_var collapse to near-zero during attack);
        - absolute cap: per-flow value above the dynamic cap is flood scale,
          rejected regardless of the provisional mean;
        - relative (PPS only): once the provisional mean has crossed the
          validity gate, values deviating more than TEA_WARMUP_REJECT_FACTOR
          are rejected.

        A sustained attack simply delays learning until it stops, which is
        the conservative outcome: no calibration under fire.
        """
        if not self._warmup_guard or len(self._samples) < TEA_WARMUP_REJECT_AFTER:
            return False
        mean = self._psum / len(self._samples)
        # Minimum value gate: reject collapsed values (attack signature)
        if self._min_learn_value is not None and value < self._min_learn_value:
            return True
        # Dynamic cap: scales with observed traffic
        dynamic_cap = max(_cfg.TEA_LEARN_CAP_FLOOR_PPS, mean * _cfg.TEA_LEARN_CAP_FACTOR)
        if value > dynamic_cap:
            return True
        # PPS-only relative guard: skip when mean is below the validity gate
        if self._min_learn_mean is None:
            return False
        if mean < self._min_learn_mean:
            return False
        ratio = value / (mean + 1e-9)
        return ratio > _cfg.TEA_WARMUP_REJECT_FACTOR or ratio < 1 / _cfg.TEA_WARMUP_REJECT_FACTOR

    def push(self, value: float, force: bool = False,
             max_drift_frac: float | None = None) -> None:
        if not self._learned:
            now = time.monotonic()
            if self._learn_started_at is None:
                self._learn_started_at = now
            if self._warmup_reject(value):
                log.debug("TEA warmup volume reject: value=%.4f", value)
                return
            self._samples.append(value)
            self._psum += value
            # Duration check removed: learn from sample count only (AWS: "minutes not hours")
            ready = (
                len(self._samples) >= self._learn_n
                and (
                    self._min_learn_mean is None
                    or self._psum / len(self._samples) >= self._min_learn_mean
                )
            )
            if ready:
                # Use recent window for mean and variance to avoid blending
                # idle and busy phases during ramping traffic
                window_size = min(_cfg.TEA_LEARN_VARIANCE_WINDOW_SIZE, len(self._samples))
                recent_samples = self._samples[-window_size:]
                self._mean     = sum(recent_samples) / len(recent_samples)
                variance_vals  = [(x - self._mean) ** 2 for x in recent_samples]
                self._variance = sum(variance_vals) / len(variance_vals)
                self._alpha    = self._compute_alpha()
                self._learned  = True
                self._baseline_history.append(self._mean)
                log.info(
                    "TEA baseline learned - mean=%.4f  std=%.4f  alpha=%.4f  (n=%d samples, window=%d)",
                    self._mean, self._std, self._alpha, len(self._samples), window_size
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
        err            = (value - self._mean) ** 2
        self._mean = new_mean
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
        # Floor: std >= 10% of mean (prevents z-score explosion from tiny variance)
        effective_std = max(self._std, abs(self._mean) * _cfg.TEA_MIN_STD_FLOOR)
        return (value - self._mean) / effective_std

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
        self.size_base  = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True)
        self.intensity_base  = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True)
        self.proto_base = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True)
        self.share_base = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True)
        self.pps_base   = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True,
                                            min_learn_mean=TEA_LEARN_MIN_MEAN_PPS)
        self.temporal_base = _AdaptiveBaseline(TEA_LEARN_MIN_SAMPLES, warmup_guard=True)
        self.last_result = {}
        self._shadow = None

    @property
    def shadow(self):
        return self._shadow

    def start_shadow(self) -> None:
        """Create a new shadow baseline."""
        if not _cfg.TEA_SHADOW_ENABLED:
            return
        self._shadow = _ShadowState()
        log.info("TEA shadow baseline created")

    def discard_shadow(self, reason: str) -> None:
        """Discard the current shadow baseline."""
        if self._shadow:
            self._shadow.discard(reason)
            self._shadow = None

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
        self.temporal_base.push(snapshot.get("temporal_entropy", 0.0), force=force,
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
            and self.temporal_base.is_learned
        )


class _ShadowState:
    """Shadow baseline that learns in parallel while primary is frozen."""

    def __init__(self):
        self.baselines = _GlobalEntropyState(TEA_WINDOW_SIZE)
        self.created_at: float = time.monotonic()
        self.sample_count: int = 0
        self.active: bool = True

    def is_ready(self) -> bool:
        """Shadow ready when all baselines learned (no duration gate)."""
        if not self.active:
            return False
        return self.baselines.is_learned

    def is_stale(self) -> bool:
        """Shadow too old, should be discarded."""
        age = time.monotonic() - self.created_at
        return age > _cfg.TEA_SHADOW_MAX_AGE_S

    def discard(self, reason: str) -> None:
        """Mark shadow inactive."""
        self.active = False
        log.info("TEA shadow discarded: %s", reason)


IP_PROFILE_MIN_SAMPLES = 30
IP_PROFILE_WINDOW      = 100
IP_PROFILE_MAX_ENTRIES = 50000

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
        if not vals or len(vals) < 2:
            return 0.0
        bins = np.histogram(vals, bins=min(10, len(vals)))
        probs = bins[0] / max(1, sum(bins[0]))
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs)))

    def verdict(self) -> str:

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

        if rising:
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
        # Option C: sustained extreme-z counter while latched. A correct
        # baseline never reads |z| >= 50 even in a real flood; only a
        # miscalibrated one does. Reaching the bound wipes the baselines.
        self._extreme_z_streak = 0
        self._multi_dim_streak = 0

        self._flow_buffer = deque(maxlen=2000)
        self._last_eval_time = 0.0
        self._eval_interval = 0.5
        self._eval_seq = 0
        self._snapshot_history = deque(maxlen=_cfg.TEA_MAHALANOBIS_HISTORY_SIZE)

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
                and self._global_state.temporal_base.locked
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
            # Snapshot last_result under lock for idle-path use
            prev_result = self._global_state.last_result

        if not current_flows:
            # Idle gap: preserve the previous result verbatim rather than
            # overwriting it with a neutral learned=False verdict.
            if prev_result:
                res = dict(prev_result)
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

        # Temporal entropy: Shannon entropy of per-flow inter-packet arrival
        # times (1/pps). Diverse pps patterns yield higher entropy.
        if ppss:
            iats = [1.0 / max(p, 1e-6) for p in ppss]
            bins = np.histogram(iats, bins=_cfg.TEA_TEMPORAL_ENTROPY_BINS)
            probs = bins[0] / max(1, sum(bins[0]))
            probs = probs[probs > 0]
            temporal_entropy = -np.sum(probs * np.log2(probs))
        else:
            temporal_entropy = 0.0

        snapshot = {
            "size_var":  size_var,
            "intensity_var": intensity_var,
            "proto_entropy": proto_entropy,
            "uniform_share": uniform_share,
            "unique_ips": len(unique_ips),
            "mean_pps": mean_pps,
            "temporal_entropy": round(temporal_entropy, 4),
        }

        # Mahalanobis distance: 6D vector capturing multi-dimensional correlation
        vector = np.array([
            size_var,
            intensity_var,
            proto_entropy,
            uniform_share,
            mean_pps,
            temporal_entropy,
        ])

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
                if len(current_flows) >= TEA_MIN_FLOWS_PER_INTERVAL:
                    state.learn(snapshot)
                res = self._neutral(size_var, intensity_var, learned=False)
                res["eval_seq"] = self._eval_seq
                state.last_result = res
                return res

            curr = state.latest()
            prev = state.previous()

            # Mahalanobis distance (thread-safe: snapshot_history accessed under lock)
            if len(self._snapshot_history) >= 30:
                history_array = np.array(self._snapshot_history)
                mean_vec = np.mean(history_array, axis=0)
                cov_matrix = np.cov(history_array.T)
                try:
                    cov_inv = np.linalg.pinv(cov_matrix + np.eye(6) * 1e-6)
                    diff = vector - mean_vec
                    mahal_dist = float(np.sqrt(diff @ cov_inv @ diff))
                except np.linalg.LinAlgError:
                    mahal_dist = 0.0
            else:
                mahal_dist = 0.0
            if mahal_dist < _cfg.TEA_MAHALANOBIS_ATTACK_THRESHOLD * 2.0:
                self._snapshot_history.append(vector)

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
                size_surge = (
                    size_base.is_high(curr["size_var"], attack_sigma)
                    and curr["size_var"] > size_base.mean * _cfg.TEA_SURGE_MIN_MAGNITUDE
                )
                intensity_surge = (
                    intensity_base.is_high(curr["intensity_var"], attack_sigma)
                    and curr["intensity_var"] > intensity_base.mean * _cfg.TEA_SURGE_MIN_MAGNITUDE
                )
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

                # Option C: sustained extreme-z while latched means the
                # baseline itself is wrong (idle cold start, regime change),
                # not that traffic is anomalous. Wipe and recalibrate. The
                # IF anomaly-rate gate blocks the restart during a real
                # flood: otherwise a sustained low-rate attack could get the
                # fresh baseline calibrated at attack scale.
                #
                # FIX: During an active attack, extreme z-scores are EXPECTED
                # (attack traffic differs from baseline). Never wipe baselines
                # mid-attack. After the attack ends, the supervised relearning
                # path handles baseline recalibration if needed.
                if self._attack_latched:
                    # During attack: always reset streak. Extreme z-scores are
                    # expected and NOT a sign of miscalibrated baselines.
                    self._extreme_z_streak = 0
                else:
                    # After attack ended: check if baselines need recalculation
                    extreme_now = (
                        max(
                            abs(size_z), abs(intensity_z), abs(proto_z),
                            abs(share_z), abs(pps_z),
                        ) >= _cfg.TEA_EXTREME_Z_SIGMA
                    )
                    if extreme_now:
                        self._extreme_z_streak += 1
                    else:
                        self._extreme_z_streak = 0

                    if self._extreme_z_streak >= _cfg.TEA_EXTREME_Z_RESTART_INTERVALS:
                        log.warning(
                            "TEA extreme-z restart: |z| >= %.0f for %d intervals - "
                            "baseline miscalibrated, using shadow promotion",
                            _cfg.TEA_EXTREME_Z_SIGMA, self._extreme_z_streak,
                        )
                        self._extreme_z_streak = 0
                        self._tea_attack_streak = 0
                        self._relearn_stable_streak = 0

                        # Try shadow promotion first (old baselines stay active)
                        if state.shadow and state.shadow.is_ready():
                            if self._shadow_health_check(state.shadow):
                                log.info("TEA extreme-z: shadow promoted (replaces miscalibrated baselines)")
                                old_state = state
                                self._global_state = state.shadow.baselines
                                # Reset window (old window mixed with new baselines causes incorrect z-scores)
                                self._global_state.window = deque(maxlen=TEA_WINDOW_SIZE)
                                self._global_state.last_result = old_state.last_result
                                old_state._shadow = None
                                # Refresh state reference to point to new baselines
                                state = self._global_state
                            else:
                                log.info("TEA extreme-z: shadow failed health check, discarding")
                                state.discard_shadow("health check failed")
                                # Activate new shadow for background learning
                                if not state.shadow:
                                    state.start_shadow()
                        else:
                            # No shadow available: activate one for background learning
                            # Old baselines stay active for IF detection
                            if not state.shadow:
                                state.start_shadow()
                                log.info("TEA extreme-z: shadow activated (old baselines still active)")
                            else:
                                log.info("TEA extreme-z: shadow exists but not ready, waiting")

                        self._set_latch(False, "extreme-z baseline restart",
                                        caller_holds_lock=True)

        size_delta  = curr["size_var"]  - prev["size_var"]
        intensity_delta = curr["intensity_var"] - prev["intensity_var"]

        if not is_learned:
            log.debug("TEA global learning phase")
            with self._lock:
                if len(current_flows) >= TEA_MIN_FLOWS_PER_INTERVAL:
                    state.learn(snapshot)
            res = self._neutral(size_var, intensity_var, learned=False)
            res["eval_seq"] = self._eval_seq
            with self._lock:
                state.last_result = res
            return res

        # Degenerate-interval guard: too few flows yield meaningless aggregate
        # stats (e.g. false "mechanized cluster"); suppress the verdict.
        degenerate = len(current_flows) < TEA_MIN_FLOWS_PER_INTERVAL
        confidence = "low"
        # P1: uniformity-only signals count as attack only with an attack-scale
        # volume companion. R1 backstops very high multi-source uniformity.
        volume_anomaly = size_surge or intensity_surge or pps_surge
        collapse_anomaly = size_collapsed or intensity_collapsed or proto_collapsed

        # Mahalanobis multi-dimensional detection (Daneshgadeh et al. 2018/2020)
        # Computed early for streak and confidence logic
        mahal_attack = mahal_dist >= _cfg.TEA_MAHALANOBIS_ATTACK_THRESHOLD
        mahal_crowd = mahal_dist >= _cfg.TEA_MAHALANOBIS_CROWD_THRESHOLD

        # Track sustained multi-dimension confirmation (score-based: 2+ signals)
        attack_signals = sum([
            size_surge,
            intensity_surge,
            pps_surge,
            mechanized_cluster,
            mahal_attack,
        ])
        if attack_signals >= 2:
            self._multi_dim_streak += 1
        else:
            self._multi_dim_streak = 0
        # Flash crowd: high volume + no collapse + not mechanized.
        # NOTE: proto_surge removed - baseline traffic already uses diverse
        # protocols (TCP/UDP/ICMP), so flash crowd proto entropy is similar
        # to baseline. mechanized_cluster already distinguishes crowds from
        # uniform attacks.
        is_flash_crowd = (
            volume_anomaly
            and not collapse_anomaly
            and not mechanized_cluster
        ) if not degenerate else False
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
            # Score-based confidence: count attack signals for flexibility
            attack_signals = sum([
                size_surge,
                intensity_surge,
                pps_surge,
                mechanized_cluster,
                mahal_attack,
            ])
            # HIGH requires sustained (3+ intervals) AND 2+ signals
            if self._multi_dim_streak >= _cfg.TEA_HIGH_CONFIDENCE_INTERVALS:
                if attack_signals >= 2:
                    confidence = "high"
                else:
                    confidence = "moderate"
            else:
                confidence = "moderate"

        # Supervised relearning (P2): a stable TEA-side "new normal" force-learns
        # the frozen baselines without IF confirmation (REG-1 caps drift and excludes
        # high-confidence snapshots so attack-scale data can't poison baselines).
        # IF anomaly rate gate removed for latched recovery: frozen baselines
        # produce false IF anomalies, creating a vicious cycle (AWS: "Post-Attack Tuning").
        if not degenerate:
            with self._lock:
                supervised = (
                    self._attack_latched
                    and self._relearn_stable_streak >= TEA_RELEARN_STABLE_INTERVALS
                    and confidence == TEA_RELEARN_MIN_CONFIDENCE
                )
            # Always learn: no gate on is_attack_pattern; robust reject (z >= 3.5)
            # in push() blocks attack-scale values from updating baselines.
            # Capped drift during attacks as defense in depth.
            with self._lock:
                state.learn(snapshot, force=False, capped=is_attack_pattern)

        # Feed shadow baseline if active and primary is frozen
        with self._lock:
            if state.shadow and state.shadow.active and self._attack_latched:
                state.shadow.baselines.learn(snapshot)
                state.shadow.sample_count += 1
                if state.shadow.is_ready():
                    log.info("TEA shadow ready for promotion (n=%d, age=%.1fs)",
                             state.shadow.sample_count,
                             time.monotonic() - state.shadow.created_at)
            # Discard stale shadows
            if state.shadow and state.shadow.is_stale():
                state.discard_shadow("too old")

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
            "temporal_entropy":  round(curr["temporal_entropy"], 4),
            "mahalanobis_distance": round(mahal_dist, 4),
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
        is_flash_crowd = tea_result.get("is_flash_crowd", False)
        is_attack = tea_result.get("is_attack_pattern", False)
        is_learned = tea_result.get("is_learned", False)

        # Flash crowd: high volume + no collapse + not mechanized + diverse
        # protocols.  Block mitigation unless flood prefilter already flagged
        # the source (IF override still applies).
        if is_flash_crowd and not is_flood_prefilter_flagged:
            with self._lock:
                self._would_block_count += 1
            log.info("TEA gate: flash crowd detected, logging only (total=%d)", self._would_block_count)
            return False

        # Existing advisory gate: learned + no attack + low confidence
        would_block = (
            not is_flood_prefilter_flagged
            and is_learned
            and not is_attack
            and tea_result.get("confidence", "low") == "low"
        )
        if would_block:
            with self._lock:
                self._would_block_count += 1
            log.info("TEA gate: normal traffic, logging only (total=%d)", self._would_block_count)
        return not would_block

    def get_flash_crowd_guidance(self) -> dict:
        """Return selective IF guidance during flash crowds.

        Decision matrix:
        - Flash crowd + low IF rate -> legitimate crowd -> ignore volume
        - Flash crowd + high IF rate -> mixed-protocol attack -> no guidance
        - No flash crowd -> no guidance
        """
        with self._lock:
            last = self._global_state.last_result
            if not last or not last.get("is_flash_crowd"):
                return {"enabled": False}

            if_anomaly_rate = self._if_anomaly_rate()
            if if_anomaly_rate >= _cfg.TEA_FLASH_CROWD_IF_THRESHOLD:
                log.info("TEA flash crowd overridden by IF rate %.2f", if_anomaly_rate)
                return {"enabled": False}

        return {
            "enabled": True,
            "ignore_volume": True,
            "keep_pattern": True,
            "keep_protocol": True,
        }

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
            # Start shadow baseline when latch locks
            self._global_state.start_shadow()
            log.info("TEA latch LOCKED (%s): tea_attack_streak=%d", reason, self._tea_attack_streak)
        else:
            self._unlock_all()
            # Try to promote shadow if ready
            self._try_promote_shadow()
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

    def _shadow_health_check(self, shadow: _ShadowState) -> bool:
        """Verify shadow baselines produce reasonable z-scores for current traffic."""
        baselines = shadow.baselines
        if not baselines.is_learned:
            return False

        # Use the latest snapshot from the shadow's window
        if not baselines.window:
            return False

        latest = baselines.window[-1]

        # Map baseline names to snapshot keys
        key_map = {
            "size": "size_var",
            "intensity": "intensity_var",
            "pps": "mean_pps",
        }

        # Check each baseline's z-score against shadow's own mean
        for name, base in [
            ("size", baselines.size_base),
            ("intensity", baselines.intensity_base),
            ("pps", baselines.pps_base),
        ]:
            if not base.is_learned:
                return False
            value = latest.get(key_map[name], 0)
            z = base.z_score(value)
            if abs(z) > 3.0:
                log.debug("TEA shadow health check failed: %s z=%.2f", name, z)
                return False

        return True

    def _try_promote_shadow(self) -> None:
        """Promote shadow baseline to primary if ready and healthy."""
        state = self._global_state
        if not state.shadow or not state.shadow.is_ready():
            return

        # Health check before promotion
        if not self._shadow_health_check(state.shadow):
            log.info("TEA shadow failed health check, discarding")
            state.discard_shadow("health check failed")
            return

        log.info("TEA shadow promoted to primary (old_mean=%.4f, new_mean=%.4f)",
                 state.size_base.mean or 0,
                 state.shadow.baselines.size_base.mean or 0)

        # Swap: shadow becomes primary
        old_state = state
        self._global_state = state.shadow.baselines
        # Reset window (old window mixed with new baselines causes incorrect z-scores)
        self._global_state.window = deque(maxlen=TEA_WINDOW_SIZE)
        self._global_state.last_result = old_state.last_result
        # Clear shadow reference
        old_state._shadow = None

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

    def _has_attack_signals(self) -> bool:
        """Check if the last TEA result has actual attack signals (volume/mechanized).
        Returns True if traffic is genuinely anomalous, False if frozen-baseline mismatch."""
        last = self._global_state.last_result
        if not last:
            return False
        return (
            last.get("size_surge", False)
            or last.get("intensity_surge", False)
            or last.get("pps_surge", False)
            or last.get("mechanized_cluster", False)
        )

    def _auto_heal_baselines(self) -> None:
        """Gradually heal frozen baselines when traffic is normal but baselines are stale.
        Called when TEA reports Anomaly with no real attack signals (frozen-baseline state).
        Uses drift-capped EMA to slowly adapt baselines to current traffic."""
        state = self._global_state
        if not state.window:
            return
        latest = state.latest()
        # Drift-capped learn: max 2% per interval, max 30% total per heal session
        state.learn(latest, force=False, capped=True)
        log.debug("TEA auto-heal: baselines adjusted (pps=%.2f, size_var=%.4f)",
                  latest.get("mean_pps", 0), latest.get("size_var", 0))

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
                # Auto-heal: if 8+ stable intervals AND no real attack signals,
                # heal baselines (frozen-baseline state, not real attack)
                if (self._relearn_stable_streak >= TEA_RELEARN_STABLE_INTERVALS
                        and not self._has_attack_signals()):
                    self._auto_heal_baselines()
                return

            if is_attack or confidence == "high":
                if not is_attack and confidence == "high":
                    is_attack = True
                self._tea_normal_streak = 0
                self._relearn_stable_streak = 0
                self._last_attack_event = time.monotonic()
                # Discard shadow baseline if an attack arrives during shadow learning
                if is_attack and self._global_state.shadow and self._global_state.shadow.active:
                    self._global_state.discard_shadow("attack during shadow learning")
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
            # Cleanup stale shadows regardless of latch state
            state = self._global_state
            if state.shadow and state.shadow.is_stale():
                state.discard_shadow("stale during idle")

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
                # Hard cap: evict oldest profiles when limit reached
                if len(self._ip_profiles) >= IP_PROFILE_MAX_ENTRIES:
                    stale = sorted(
                        self._ip_profiles.items(),
                        key=lambda x: x[1]._last_update
                    )[:len(self._ip_profiles) // 10]
                    for ip, _ in stale:
                        del self._ip_profiles[ip]
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
            "temporal_entropy":  0.0,
            "mahalanobis_distance": 0.0,
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
            "eval_seq":           0,
        }

# Module-level singleton
entropy_analyzer = EntropyAnalyzer()
