import math
import warnings
import numpy as np
import threading
from backend.models import loader

_median_lock       = threading.Lock()
_feature_sums      = None
_feature_counts    = None
_feature_medians   = None
_thread_local       = threading.local()
_BATCH_FLUSH_SIZE   = 20   # flush thread-local buffer to shared state every N calls


def _init_median_tracker(n: int) -> None:
    global _feature_sums, _feature_counts, _feature_medians
    _feature_sums    = np.zeros(n, dtype=np.float64)
    _feature_counts  = np.zeros(n, dtype=np.int64)
    _feature_medians = np.zeros(n, dtype=np.float64)


def _get_local_buffer(n: int):
    # Per-thread accumulator — avoids locking on every single flow
    if not hasattr(_thread_local, "sums"):
        _thread_local.sums   = np.zeros(n, dtype=np.float64)
        _thread_local.counts = np.zeros(n, dtype=np.int64)
        _thread_local.calls  = 0
    return _thread_local


def _update_medians(vec: np.ndarray) -> None:
    # Accumulate locally, only take the lock every _BATCH_FLUSH_SIZE calls
    n  = vec.shape[0]
    tl = _get_local_buffer(n)
    mask = np.isfinite(vec)
    tl.sums[mask]   += vec[mask]
    tl.counts[mask] += 1
    tl.calls += 1

    if tl.calls >= _BATCH_FLUSH_SIZE:
        with _median_lock:
            _feature_sums[:]   += tl.sums
            _feature_counts[:] += tl.counts
            np.divide(_feature_sums, np.maximum(_feature_counts, 1),
                      out=_feature_medians)
        tl.sums[:]   = 0
        tl.counts[:] = 0
        tl.calls = 0


def _get_medians() -> np.ndarray:
    with _median_lock:
        return _feature_medians.copy()


def extract_if_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,16) feature matrix matching feature_contract.json order."""
    loader.require_loaded()

    n = len(loader.if_features)
    if _feature_sums is None:
        _init_median_tracker(n)

    s   = flow_stats
    eps = 1e-9

    # --- Raw fields ---
    fds  = float(s.get("flow_duration_sec",        0))
    fdns = float(s.get("flow_duration_nsec",       0))
    pkt  = float(s.get("packet_count",             0))
    byt  = float(s.get("byte_count",               0))
    pps  = float(s.get("packet_count_per_second",  0))
    bps  = float(s.get("byte_count_per_second",    0))
    fcps = float(s.get("flow_count_per_src",       0))
    tps  = float(s.get("tp_src",                   0))
    tpd  = float(s.get("tp_dst",                   0))
    ipr  = float(s.get("ip_proto",                 0))

    # --- Engineered features ---
    pkt_byte_rate_ratio = math.log1p(max(pps / (bps + eps), 0))
    avg_bytes_per_pkt   = byt / (pkt + eps)
    flow_intensity      = math.log1p(max(pkt * bps, 0))          # uses bps, not pps
    port_entropy        = math.log1p(max(tps / (tpd + 1), 0))
    bytes_per_duration  = math.log1p(max(byt / (fds + eps), 0))
    # eps here, not +1 — matches training denominator exactly
    pkt_size_uniformity = math.log1p(max(avg_bytes_per_pkt / (bps + eps), 0))
    flow_src_intensity  = math.log1p(max(fcps * pps, 0))

    # --- Build vector in contract order ---
    vec = np.array([
        math.log1p(max(fds,  0)),   # flow_duration_sec
        math.log1p(max(pkt,  0)),   # packet_count
        math.log1p(max(byt,  0)),   # byte_count
        math.log1p(max(pps,  0)),   # packet_count_per_second
        math.log1p(max(bps,  0)),   # byte_count_per_second
        math.log1p(max(fcps, 0)),   # flow_count_per_src
        math.log1p(max(tps,  0)),   # tp_src
        math.log1p(max(tpd,  0)),   # tp_dst
        ipr,                       # ip_proto
        pkt_byte_rate_ratio,
        avg_bytes_per_pkt,
        flow_intensity,
        port_entropy,
        bytes_per_duration,
        pkt_size_uniformity,
        flow_src_intensity,
    ], dtype=np.float64)

    # Replace inf/-inf with NaN then fill with running median
    vec = np.where(np.isfinite(vec), vec, np.nan)
    _update_medians(vec)
    nans = np.isnan(vec)
    if nans.any():
        vec[nans] = _get_medians()[nans]

    # Two-stage numpy scaling avoids the per-item DataFrame hot path; float64
    # input matches the fitted scalers byte-for-byte.
    global _last_raw_vec
    _last_raw_vec = vec

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", message="X does not have valid feature names",
            category=UserWarning)
        X_rob = loader.if_scaler.transform(vec.reshape(1, -1))
        return loader.if_quantiler.transform(X_rob)   # shape (1, 16)


def run_if_inference_batch(vecs_scaled: list) -> list[tuple[float, bool]]:
    """Batch (-score_samples) over stacked rows; preserves input order."""
    loader.require_loaded()
    if not vecs_scaled:
        return []
    stacked = np.vstack([np.asarray(v, dtype=np.float64).reshape(1, -1)
                         for v in vecs_scaled])
    scores = -loader.if_model.score_samples(stacked)
    return [(float(s), bool(s >= loader.if_threshold)) for s in scores]


def run_if_inference(vec_scaled: np.ndarray) -> tuple[float, bool]:
    """Return (if_score, is_anomaly)."""
    loader.require_loaded()
    if_score   = float(-loader.if_model.score_samples(vec_scaled)[0])
    is_anomaly = if_score >= loader.if_threshold
    return if_score, is_anomaly