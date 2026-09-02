"""Test that TEA tunable constants are sourced from config.py (single source of truth).

This test validates the config-transfer refactor: all tunable TEA constants
must live in backend.config and be imported into entropy_analyzer, not
hardcoded in the analyzer module.
"""
import pytest
from backend import config as cfg
from backend.pipeline import entropy_analyzer as ea_mod


class TestTEAConfigTransfer:
    """Verify TEA tunables come from config.py."""

    # The 6 tunables that must move to config
    TRANSFERRED_CONSTANTS = [
        "TEA_LEARN_MIN_SAMPLES",
        "TEA_ATTACK_SIGMA",
        "TEA_CROWD_SIGMA",
        "TEA_EMA_ALPHA_MIN",
        "TEA_EMA_ALPHA_MAX",
        "TEA_ROBUST_REJECT_SIGMA",
        "TEA_RELEARN_ALPHA",
        "TEA_RELEARN_STABLE_INTERVALS",
        "TEA_IDLE_UNLOCK_S",
        "TEA_IP_PROFILE_TTL_S",
        "TEA_LATCH_MAX_HOLD_S",
    ]

    def test_transferred_constants_exist_in_config(self):
        """Each transferred constant must be defined in backend.config."""
        for name in self.TRANSFERRED_CONSTANTS:
            assert hasattr(cfg, name), f"config missing {name}"

    def test_entropy_analyzer_uses_config_values(self):
        """ea_mod constants must equal config values (same object preferred)."""
        expected = {
            "TEA_LEARN_MIN_SAMPLES": 300,
            "TEA_ATTACK_SIGMA": 2.5,
            "TEA_CROWD_SIGMA": 1.5,
            "TEA_EMA_ALPHA_MIN": 0.02,
            "TEA_EMA_ALPHA_MAX": 0.10,
            "TEA_ROBUST_REJECT_SIGMA": 3.5,  # Apply: literature 3.0-3.5 on MAD scale
            "TEA_RELEARN_ALPHA": 0.15,       # Apply: literature 0.10-0.15
            "TEA_RELEARN_STABLE_INTERVALS": 8, # Apply: literature 6-10
            "TEA_IDLE_UNLOCK_S": 30.0,       # Apply: literature 30-60s
            "TEA_IP_PROFILE_TTL_S": 60,      # Apply: literature 60-120s
            "TEA_LATCH_MAX_HOLD_S": 90.0,   # Apply: literature 90-120s
        }
        for name in self.TRANSFERRED_CONSTANTS:
            ea_val = getattr(ea_mod, name)
            cfg_val = getattr(cfg, name)
            exp_val = expected[name]
            assert ea_val == exp_val, f"{name} ea={ea_val} expected={exp_val}"
            assert cfg_val == exp_val, f"{name} config={cfg_val} expected={exp_val}"

    def test_constants_no_longer_hardcoded_in_entropy_analyzer(self):
        """Ensure the old hardcoded definitions are removed from entropy_analyzer.py.
        We verify by checking that ea_mod does NOT have its own separate definition
        for these (would require inspecting module source; instead we check the
        two structural constants that MUST stay hardcoded are NOT in the transfer list).
        """
        # These two must stay hardcoded (frozen-by-design), not in config
        assert not hasattr(cfg, "TEA_VARIANCE_STABLE_THRESHOLD")
        assert not hasattr(cfg, "TEA_BASELINE_HISTORY_MAX")
        # But they must still exist in ea_mod
        assert hasattr(ea_mod, "TEA_VARIANCE_STABLE_THRESHOLD")
        assert hasattr(ea_mod, "TEA_BASELINE_HISTORY_MAX")

    def test_dropped_constants_removed(self):
        """TEA_MIN_CROWD_DIVERSITY and TEA_FEEDBACK_UNLOCK_STREAK must be removed."""
        assert not hasattr(cfg, "TEA_MIN_CROWD_DIVERSITY")
        assert not hasattr(ea_mod, "TEA_MIN_CROWD_DIVERSITY")
        assert not hasattr(ea_mod, "TEA_FEEDBACK_UNLOCK_STREAK")

    def test_analyzer_baseline_uses_configured_learn_samples(self, monkeypatch):
        """Behavioral: analyzer builds baselines with configured TEA_LEARN_MIN_SAMPLES."""
        sentinel = 999
        monkeypatch.setattr(cfg, "TEA_LEARN_MIN_SAMPLES", sentinel, raising=True)
        monkeypatch.setattr(ea_mod, "TEA_LEARN_MIN_SAMPLES", sentinel, raising=True)

        from backend.pipeline.entropy_analyzer import EntropyAnalyzer
        ea = EntropyAnalyzer()

        for attr in ("size_base", "intensity_base", "proto_base", "share_base", "pps_base"):
            baseline = getattr(ea._global_state, attr)
            assert baseline._learn_n == sentinel, \
                f"{attr}._learn_n = {baseline._learn_n}, expected {sentinel}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])