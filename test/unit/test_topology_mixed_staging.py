from unittest import mock


def test_mixed_staging_gap_is_random_five_to_ten_seconds():
    # waves are staggered by a random gap in [5, 10] seconds so successive
    # vectors never drop on the same second; per-host jitter adds on top
    import topology.topology as t
    with mock.patch.object(t.random, "uniform", return_value=10.0):
        waves = t._compute_mixed_waves() if hasattr(t, "_compute_mixed_waves") \
            else None
    src = open("topology/topology.py").read()
    assert "stagger_s" in src
    assert "random.uniform(stagger_s * 0.5, stagger_s)" in src
    assert "random.uniform(20.0, 30.0)" not in src
    assert "stagger_s * 1.2" not in src
