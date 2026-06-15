import numpy as np
import pandas as pd
from backend.models import loader


def extract_rf_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,17) feature matrix matching rf_feature_contract.json order."""
    loader.require_loaded()

    s   = flow_stats
    eps = 1e-9

    # --- Raw fields ---
    fds  = float(s.get("flow_duration_sec",        0))
    fdns = float(s.get("flow_duration_nsec",       0))
    ito  = float(s.get("idle_timeout",             0))
    hto  = float(s.get("hard_timeout",             0))
    flg  = float(s.get("flags",                    0))
    pkt  = float(s.get("packet_count",             0))
    byt  = float(s.get("byte_count",               0))
    pps  = float(s.get("packet_count_per_second",  0))
    bps  = float(s.get("byte_count_per_second",    0))
    fcps = float(s.get("flow_count_per_src",       0))
    ipr  = float(s.get("ip_proto",                 0))

    # --- Engineered features ---
    # pkt_byte_rate_ratio
    pkt_byte_rate_ratio = np.log1p(max(pps / (bps + eps), 0))

    # duration_pkt_ratio — uses total duration in ns
    fdt = fds * 1e9 + fdns   # raw ns
    fdt_log = np.log1p(max(fdt, 0))
    duration_pkt_ratio = np.log1p(max(fdt_log / (pkt + eps), 0)) if pkt > 0 else 0.0

    # pkt_rate_per_duration
    pkt_rate_per_duration = np.log1p(max(pkt / (fdt_log + eps), 0))

    # avg_bytes_per_pkt
    avg_bytes_per_pkt = byt / (pkt + eps)

    # flow_intensity = pkt * bps
    flow_intensity = np.log1p(max(pkt * bps, 0))

    # bytes_per_duration
    bytes_per_duration = np.log1p(max(byt / (fds + eps), 0))

    # pkt_size_uniformity
    pkt_size_uniformity = np.log1p(max(avg_bytes_per_pkt / (bps + 1), 0))

    # flow_src_intensity = flow_count_per_src * pps
    flow_src_intensity = np.log1p(max(fcps * pps, 0))

    # --- Build vector in contract order ---
    vec = np.array([
        np.log1p(max(fds,  0)),   # flow_duration_sec
        ito,                       # idle_timeout
        hto,                       # hard_timeout
        flg,                       # flags
        np.log1p(max(pkt,  0)),   # packet_count
        np.log1p(max(byt,  0)),   # byte_count
        np.log1p(max(pps,  0)),   # packet_count_per_second
        np.log1p(max(bps,  0)),   # byte_count_per_second
        np.log1p(max(fcps, 0)),   # flow_count_per_src
        ipr,                       # ip_proto
        pkt_byte_rate_ratio,       # pkt_byte_rate_ratio
        duration_pkt_ratio,        # duration_pkt_ratio
        pkt_rate_per_duration,     # pkt_rate_per_duration
        avg_bytes_per_pkt,         # avg_bytes_per_pkt
        flow_intensity,            # flow_intensity
        bytes_per_duration,        # bytes_per_duration
        pkt_size_uniformity,       # pkt_size_uniformity
        flow_src_intensity,        # flow_src_intensity
    ], dtype=np.float64)

    # Replace inf/-inf with 0 — RF robust to missing stats
    vec = np.where(np.isfinite(vec), vec, 0.0)

    df = pd.DataFrame(vec.reshape(1, -1), columns=loader.rf_features)
    return loader.rf_scaler.transform(df)   # shape (1, 17)


def run_rf_inference(vec_scaled: np.ndarray) -> tuple[str, float]:
    """Return (attack_class_or_Uncertain, confidence)."""
    loader.require_loaded()

    proba = loader.rf_model.predict_proba(vec_scaled)[0]
    idx   = int(np.argmax(proba))
    conf  = float(proba[idx])

    if conf >= loader.rf_conf_gate:
        attack_class = loader.rf_encoder.inverse_transform([idx])[0]
    else:
        attack_class = "Uncertain"

    return attack_class, conf