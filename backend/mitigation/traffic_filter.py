import logging

from backend.config import SIMULATION_MODE

log = logging.getLogger(__name__)

# ── Ban durations per level ────────────────────────────────────────────────
# state_machine calls get_ban_duration(ban_level) — never hardcodes durations
if SIMULATION_MODE:
    BAN_LEVELS = [30, 60, 120, 300, 600, 1200]       # 30s → 20m
else:
    BAN_LEVELS = [120, 300, 600, 1800, 3600, 86400]  # 2m → 24h

MAX_BAN_LEVEL      = len(BAN_LEVELS) - 1

# Phase 3 blackhole TTL
BLACKHOLE_TTL_SECONDS = 3600  # 1 hour


def get_ban_duration(ban_level: int) -> int:
    # Returns ban duration in seconds for the given level.
    # Clamps to MAX_BAN_LEVEL if out of range.
    level = max(0, min(ban_level, MAX_BAN_LEVEL))
    return BAN_LEVELS[level]


def get_blackhole_ttl() -> int:
    # Returns blackhole TTL in seconds.
    return BLACKHOLE_TTL_SECONDS


# ── Action constants sent verbatim to ZmqCommander → Ryu ──────────────────
ACTION_QUARANTINE = "quarantine"   # priority-90 drop rule
ACTION_RATE_LIMIT = "rate_limit"   # priority-80 meter rule
ACTION_BLOCK      = "block"        # priority-100 full drop
ACTION_REDIRECT   = "redirect"     # priority-85 redirect to sinkhole
ACTION_CLEAR      = "clear"        # removes all rules for this IP

# IP is sinkholes when confidence is below this threshold
SINKHOLE_CONFIDENCE_THRESHOLD = 0.70


def resolve_phase1_actions(priority: str) -> list[str]:
    # Both quarantine + rate_limit sent simultaneously on Phase 1 entry.
    # quarantine (90): aggressive drop
    # rate_limit (80): secondary containment
    # priority reserved for future per-severity tuning
    return [ACTION_QUARANTINE, ACTION_RATE_LIMIT]


def resolve_ban_action(ban_duration_sec: int) -> tuple[str, int]:
    # Full block for Phase 2 time ban
    return ACTION_BLOCK, ban_duration_sec


def resolve_blackhole_action(ttl_sec: int) -> tuple[str, int]:
    # Full block for Phase 3 blackhole
    return ACTION_BLOCK, ttl_sec


def resolve_sinkhole_action(sinkhole_ip: str) -> dict:
    # Redirect command requires extra redirect_to field for Ryu
    return {
        "action":      ACTION_REDIRECT,
        "redirect_to": sinkhole_ip,
    }


def resolve_release_action() -> str:
    # Removes all FlowMod rules for this IP
    return ACTION_CLEAR


def should_sinkhole(attack_vector: str, confidence: float, phase: int) -> bool:
    # Sinkhole rule (approved):
    #   attack_vector == "Uncertain" AND confidence < 0.60
    #   AND not already in Phase 2/3 (never downgrade a banned IP)
    if phase >= 2:
        return False

    result = (attack_vector == "Uncertain") and (confidence < SINKHOLE_CONFIDENCE_THRESHOLD)

    if result:
        log.debug("TrafficFilter: sinkhole — vector=%s  conf=%.2f", attack_vector, confidence)

    return result


def log_action(src_ip: str, action: str, phase: int, reason: str = "") -> None:
    log.info("TrafficFilter [%s] action=%s  phase=%d  %s", src_ip, action, phase, reason)