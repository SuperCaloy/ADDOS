import numpy as np
import threading
import pandas as pd
from backend.models import loader

_median_lock     = threading.Lock()
_feature_sums    = None
_feature_counts  = None
_feature_medians = None


def _init_median_tracker(n: int) -> None:
    global _feature_sums, _feature_counts, _feature_medians
    _feature_sums    = np.zeros(n, dtype=np.float64)
    _feature_counts  = np.zeros(n, dtype=np.int64)
    _feature_medians = np.zeros(n, dtype=np.float64)


def _update_medians(vec: np.ndarray) -> None:
    # Incremental mean as stable median approximation
    with _median_lock:
        mask = np.isfinite(vec)
        _feature_counts[mask] += 1
        _feature_sums[mask]   += vec[mask]
        np.divide(_feature_sums, np.maximum(_feature_counts, 1),
                  out=_feature_medians)


def _get_medians() -> np.ndarray:
    with _median_lock:
        return _feature_medians.copy()


def extract_if_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,17) feature matrix matching feature_contract.json order."""
    loader.require_loaded()

    n = len(loader.if_features)
    if _feature_sums is None:
        _init_median_tracker(n)

    s   = flow_stats
    eps = 1e-9

    # --- Raw fields ---
    fds  = float(s.get("flow_duration_sec",        0))
    fdns = float(s.get("flow_duration_nsec",       0))
    flg  = float(s.get("flags",                    0))
    pkt  = float(s.get("packet_count",             0))
    byt  = float(s.get("byte_count",               0))
    pps  = float(s.get("packet_count_per_second",  0))
    bps  = float(s.get("byte_count_per_second",    0))
    fcps = float(s.get("flow_count_per_src",       0))
    tps  = float(s.get("tp_src",                   0))
    tpd  = float(s.get("tp_dst",                   0))
    ipr  = float(s.get("ip_proto",                 0))

    # --- Engineered features ---
    pkt_byte_rate_ratio = np.log1p(max(pps / (bps + eps), 0))
    avg_bytes_per_pkt   = byt / (pkt + eps)
    flow_intensity      = np.log1p(max(pkt * bps, 0))          # fixed: bps not pps
    port_entropy        = np.log1p(max(tps / (tpd + 1), 0))
    bytes_per_duration  = np.log1p(max(byt / (fds + eps), 0))
    pkt_size_uniformity = np.log1p(max(avg_bytes_per_pkt / (bps + 1), 0))
    flow_src_intensity  = np.log1p(max(fcps * pps, 0))

    # --- Build vector in contract order ---
    vec = np.array([
        np.log1p(max(fds,  0)),   # flow_duration_sec
        flg,                       # flags
        np.log1p(max(pkt,  0)),   # packet_count
        np.log1p(max(byt,  0)),   # byte_count
        np.log1p(max(pps,  0)),   # packet_count_per_second
        np.log1p(max(bps,  0)),   # byte_count_per_second
        np.log1p(max(fcps, 0)),   # flow_count_per_src
        np.log1p(max(tps,  0)),   # tp_src
        np.log1p(max(tpd,  0)),   # tp_dst
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

    # Two-stage scaling: RobustScaler → QuantileTransformer (matches training)
    df      = pd.DataFrame(vec.reshape(1, -1), columns=loader.if_features)
    X_rob   = loader.if_scaler.transform(df)
    return loader.if_quantiler.transform(X_rob)   # shape (1, 17)


def run_if_inference(vec_scaled: np.ndarray) -> tuple[float, bool]:
    """Return (if_score, is_anomaly)."""
    loader.require_loaded()
    if_score   = float(-loader.if_model.score_samples(vec_scaled)[0])
    is_anomaly = if_score >= loader.if_threshold
    return if_score, is_anomaly