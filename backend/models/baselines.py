# Training derived normal references for Threat Analysis signal cards.
# Replaces hardcoded frontend display cutoffs with medians and IQRs from the
# fitted Isolation Forest RobustScaler, served through /api/ip_detail.
import functools
import json
import math

# Display key -> training contract feature plus the transform the IF
# pipeline applies before scaling. Frontend values are raw display units.
DISPLAY_FEATURES = {
    'pps':                {'contract': 'packet_count_per_second', 'transform': 'log1p'},
    'byte_rate':          {'contract': 'byte_count_per_second',   'transform': 'log1p'},
    'pkt_count':          {'contract': 'packet_count',            'transform': 'log1p'},
    'byte_count':         {'contract': 'byte_count',              'transform': 'log1p'},
    'bpp':                {'contract': 'avg_bytes_per_pkt',       'transform': 'identity'},
    'flow_intensity':     {'contract': 'flow_intensity',          'transform': 'log1p'},
    'bytes_per_duration': {'contract': 'bytes_per_duration',      'transform': 'log1p'},
}

# Features deliberately excluded from deviation alerting in v1, with reasons.
EXCLUDED_FEATURES = {
    'port_entropy': 'training spread explodes (median+3IQR overflows display range)',
    'pkt_size_uniformity': 'alert direction is inverted (low means uniform); separate handling required',
    'ip_proto': 'categorical protocol code, never displayed as a signal card',
}

# Single documented alert rule: deviation at or above this many IQRs.
ALERT_DEVIATION = 3.0


def _apply_transform(raw_value: float, transform: str) -> float:
    if transform == 'log1p':
        return math.log1p(max(raw_value, 0.0))
    return float(raw_value)


def _invert_transform(trans_value: float, transform: str) -> float:
    if transform == 'log1p':
        return math.expm1(trans_value)
    return float(trans_value)


def build_references(center, scale, names) -> dict:
    """Builds per display key references from scaler stats in contract order."""
    med_by_feat = dict(zip(names, center))
    iqr_by_feat = dict(zip(names, scale))
    refs = {}
    for key, spec in DISPLAY_FEATURES.items():
        median_t = float(med_by_feat[spec['contract']])
        refs[key] = {
            'median': _invert_transform(median_t, spec['transform']),
            'median_t': median_t,
            'iqr': float(iqr_by_feat[spec['contract']]),
            'transform': spec['transform'],
        }
    return refs


@functools.lru_cache(maxsize=1)
def references_from_artifacts() -> dict:
    """Derives references once from the fitted IF scaler and contract."""
    import joblib
    from backend.config import IF_CONTRACT_PATH, IF_SCALER_PATH
    with open(IF_CONTRACT_PATH) as f:
        names = json.load(f)['feature_names']
    scaler = joblib.load(IF_SCALER_PATH)
    return build_references(scaler.center_, scaler.scale_, names)


def deviation_of(raw_value: float, ref: dict) -> float:
    """IQRs above training median, in transform space. Zero IQR never alerts."""
    if not ref['iqr'] > 0:
        return 0.0
    return (_apply_transform(raw_value, ref['transform']) - ref['median_t']) / ref['iqr']


def alert_value(key: str, refs: dict, k: float = ALERT_DEVIATION) -> float:
    """Raw display value at which deviation reaches k. Audit helper."""
    ref = refs[key]
    return _invert_transform(ref['median_t'] + k * ref['iqr'], ref['transform'])


def deviations_for(quantities: dict, refs: dict) -> dict:
    """Scores raw display quantities against references. Keys must match."""
    return {key: deviation_of(value, refs[key]) for key, value in quantities.items()}


def signal_quantities(stats: dict) -> dict:
    """Maps raw flow stats to raw deviation inputs per display key.

    Composite quantities are recomputed from raw counts here so the
    log1p transform in deviation_of applies exactly once.
    """
    pkt_count = stats.get('packet_count', 0) or 0
    byte_count = stats.get('byte_count', 0) or 0
    byte_rate = stats.get('byte_count_per_second', 0) or 0
    duration = stats.get('flow_duration_sec', 0) or 0
    bpp = stats.get('bytes_per_packet')
    if bpp is None:
        bpp = byte_count / max(int(pkt_count), 1)
    return {
        'pps': stats.get('packet_count_per_second', 0) or 0,
        'byte_rate': byte_rate,
        'pkt_count': pkt_count,
        'byte_count': byte_count,
        'bpp': bpp,
        'flow_intensity': max(int(pkt_count), 1) * byte_rate,
        'bytes_per_duration': byte_count / max(duration or 1, 1),
    }


def alert_on(deviation: float, k: float = ALERT_DEVIATION) -> bool:
    return bool(deviation >= k)
