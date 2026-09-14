"""RED tests for backend served signal baselines.

Plan: notes/tasks/backend-served-signal-baselines-plan.md
Run: python3 -m pytest tests/test_signal_baselines.py -v
"""
import math

import pytest

from backend.models import baselines


def test_display_keys_cover_all_card_features():
    assert set(baselines.DISPLAY_FEATURES) == {
        'pps', 'byte_rate', 'pkt_count', 'byte_count', 'bpp',
        'flow_intensity', 'bytes_per_duration',
    }


def test_excluded_features_carry_reasons():
    for key in ('port_entropy', 'pkt_size_uniformity', 'ip_proto'):
        assert key in baselines.EXCLUDED_FEATURES
        assert len(baselines.EXCLUDED_FEATURES[key]) > 0


def test_build_references_matches_real_training_medians():
    refs = baselines.references_from_artifacts()
    assert refs['pkt_count']['median'] == pytest.approx(33.0)
    assert refs['byte_rate']['median'] == pytest.approx(52.14, rel=1e-3)
    assert refs['pps']['median'] == pytest.approx(0.3766, rel=1e-3)
    assert refs['byte_count']['median'] == pytest.approx(8999.0)


def test_deviation_is_zero_at_the_median():
    refs = baselines.references_from_artifacts()
    for key, ref in refs.items():
        assert baselines.deviation_of(ref['median'], ref) == pytest.approx(0.0)


def test_alert_threshold_lands_near_legacy_cutoffs():
    refs = baselines.references_from_artifacts()
    assert baselines.alert_value('byte_count', refs) == pytest.approx(1.331e6, rel=1e-2)
    assert baselines.alert_value('pkt_count', refs) == pytest.approx(13110.0, rel=1e-2)


def test_log_feature_deviation_uses_transform_space():
    ref = {'median_t': math.log1p(100.0), 'iqr': 1.0, 'transform': 'log1p'}
    assert baselines.deviation_of(100.0, ref) == pytest.approx(0.0)
    assert baselines.deviation_of(math.expm1(math.log1p(100.0) + 2.0), ref) == pytest.approx(2.0)


def test_identity_feature_deviation_is_raw_distance():
    ref = {'median_t': 100.0, 'iqr': 50.0, 'transform': 'identity'}
    assert baselines.deviation_of(250.0, ref) == pytest.approx(3.0)


def test_zero_iqr_never_alerts():
    ref = {'median_t': 1.0, 'iqr': 0.0, 'transform': 'log1p'}
    assert baselines.deviation_of(1e12, ref) == 0.0


def test_deviations_for_scores_a_flow():
    refs = baselines.references_from_artifacts()
    devs = baselines.deviations_for({'pps': 22600.0, 'byte_rate': 33800.0}, refs)
    assert devs['pps'] > baselines.ALERT_DEVIATION
    assert set(devs) == {'pps', 'byte_rate'}


def test_alert_rule_is_single_documented_constant():
    assert baselines.ALERT_DEVIATION == 3.0
    assert baselines.alert_on(3.0) is True
    assert baselines.alert_on(2.999) is False


def test_signal_quantities_map_flow_stats_to_raw_inputs():
    quantities = baselines.signal_quantities({
        'packet_count': 1000, 'byte_count': 200000,
        'packet_count_per_second': 500.0, 'byte_count_per_second': 100000.0,
        'bytes_per_packet': 200.0, 'flow_duration_sec': 4.0,
    })
    assert quantities['pps'] == 500.0
    assert quantities['byte_rate'] == 100000.0
    assert quantities['pkt_count'] == 1000
    assert quantities['byte_count'] == 200000
    assert quantities['bpp'] == 200.0
    assert quantities['flow_intensity'] == 1000 * 100000.0
    assert quantities['bytes_per_duration'] == pytest.approx(50000.0)


def test_signal_quantities_cover_every_display_key():
    quantities = baselines.signal_quantities({
        'packet_count': 10, 'byte_count': 1000,
        'packet_count_per_second': 5.0, 'byte_count_per_second': 500.0,
        'bytes_per_packet': 100.0, 'flow_duration_sec': 2.0,
    })
    assert set(quantities) == set(baselines.DISPLAY_FEATURES)
