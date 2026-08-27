"""T13: hot-path feature extraction equivalence.

V1 removes the per-item pd.DataFrame from extract_if_features and
extract_rf_features. Output must stay byte-identical to the pandas
reference path (recomputed here independently), because model decisions
depend on exact feature values.
"""
import warnings

import numpy as np
import pandas as pd
import pytest


def _flow(seed=0):
    return {
        "flow_duration_sec": 6.0 + seed,
        "flow_duration_nsec": 12 + seed,
        "packet_count": 50000 + seed * 7,
        "byte_count": 2500000 + seed * 111,
        "packet_count_per_second": 9000.0 + seed,
        "byte_count_per_second": 400000.0 + seed * 3,
        "flow_count_per_src": 3 + (seed % 4),
        "ip_proto": 6 + (seed % 3),
        "tp_src": 44444 + seed,
        "tp_dst": 80,
    }


def _pandas_if_reference(raw_vec, loader):
    """Byte-identical replica of the OLD if_pipeline tail."""
    df = pd.DataFrame(raw_vec.reshape(1, -1), columns=loader.if_features)
    X_rob = loader.if_scaler.transform(df)
    return loader.if_quantiler.transform(X_rob)


def test_if_features_match_pandas_reference(real_models):
    from backend.models import if_pipeline, loader

    for seed in range(8):
        scaled = if_pipeline.extract_if_features(_flow(seed))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ref = _pandas_if_reference(if_pipeline._last_raw_vec, loader)
        assert np.array_equal(scaled, ref), f"seed {seed} diverged"


def _pandas_rf_reference(raw_vec, loader):
    """Byte-identical replica of the OLD rf_pipeline tail."""
    df = pd.DataFrame(raw_vec.reshape(1, -1), columns=loader.rf_features)
    return loader.rf_scaler.transform(df)


def test_rf_features_match_pandas_reference(real_models):
    from backend.models import rf_pipeline, loader

    for seed in range(8):
        scaled = rf_pipeline.extract_rf_features(_flow(seed))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ref = _pandas_rf_reference(rf_pipeline._last_raw_vec, loader)
        assert np.array_equal(scaled, ref), f"seed {seed} diverged"
