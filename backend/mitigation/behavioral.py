import logging
from backend.database import writer

log = logging.getLogger(__name__)

# ── Thresholds ─────────────────────────────────────────────────────────────
# Weighted offense score that triggers direct blackhole (half-life decay, 24h)
# Score = sum of (2.0 * 0.5^(hours_elapsed/24)) per offense
# Needs burst/repeat attacks to reach 5.0 — casual probing decays below threshold
BLACKHOLE_OFFENSE_THRESHOLD = 5.0

# IF score that always forces High priority
HIGH_PRIORITY_IF_THRESHOLD  = 0.75

# IF score that forces High priority only for repeat offenders (2+ offenses)
REPEAT_HIGH_PRIORITY_IF     = 0.65


def record_offense(src_ip: str, attack_vector: str, if_score: float,
                   confidence: float, priority: str,
                   phase_reached: int, first_seen: str,
                   unblock_reason: str = "Auto-Released",
                   ban_level: int = 0, offence_count: int = 1) -> None:
    # Write completed offense to ip_attack_history.
    # Called by state_machine._clear() so history persists across restarts.
    try:
        writer.log_attack_history(
            src_ip         = src_ip,
            attack_vector  = attack_vector,
            if_score       = if_score,
            confidence     = confidence,
            priority       = priority,
            phase_reached  = phase_reached,
            first_seen     = first_seen,
            unblock_reason = unblock_reason,
            ban_level      = ban_level,
            offence_count  = offence_count,
        )
        log.debug("Behavioral: offense recorded — %s  vector=%s  phase=%d",
                  src_ip, attack_vector, phase_reached)
    except Exception as exc:
        log.warning("Behavioral: failed to record offense for %s — %s", src_ip, exc)


def get_decay_score(src_ip: str) -> float:
    # Reuses writer.get_offense_count — already implements half-life decay.
    # Score = sum of (2.0 * 0.5^(hours_elapsed/24)) per offence.
    # Fresh offence ~2.0, 24h ago ~1.0, 48h ago ~0.5
    try:
        return writer.get_offense_count(src_ip)
    except Exception as exc:
        log.warning("Behavioral: decay score failed for %s — %s", src_ip, exc)
        return 0.0


def get_offence_count(src_ip: str) -> int:
    # Raw count — literal number of times this IP has offended.
    try:
        count = writer.get_offense_total_count(src_ip)
        return count if count is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get offence count for %s — %s", src_ip, exc)
        return 0


def get_offences(src_ip: str) -> int:
    # Query total offense count for this IP from ip_attack_history.
    # Returns 0 on no history or DB error.
    try:
        count = writer.get_offense_total_count(src_ip)
        return count if count is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get offenses for %s — %s", src_ip, exc)
        return 0


def get_ban_level(src_ip: str) -> int:
    # Query last recorded ban level for this IP from DB.
    # Returns 0 if no history.
    try:
        level = writer.get_ban_level(src_ip)
        return level if level is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get ban level for %s — %s", src_ip, exc)
        return 0


def is_known_offender(src_ip: str) -> bool:
    # True if IP has any prior offense in DB.
    # Used by state_machine to route returning attackers via on_reoffence().
    return get_offences(src_ip) > 0


def should_blackhole(src_ip: str, current_ban_level: int) -> bool:
    # Returns True if IP should skip ban escalation and go straight to blackhole.
    # Triggers when:
    #   - weighted offense score >= BLACKHOLE_OFFENSE_THRESHOLD (persistent offender)
    #   - score uses half-life decay — needs burst/recent attacks to trigger
    offense_score = get_offences(src_ip)
    if offense_score >= BLACKHOLE_OFFENSE_THRESHOLD:
        log.info("Behavioral: %s score=%.2f >= %.1f → blackhole",
                 src_ip, offense_score, BLACKHOLE_OFFENSE_THRESHOLD)
        return True
    return False


def assign_priority(if_score: float, confidence: float, src_ip: str = "") -> str:
    # High if: confirmed attack (IF>=0.75 AND conf>=0.80)
    #          repeat offender (2+ offences)
    #          persistent attacker (decay score >= 3.0)
    if if_score >= HIGH_PRIORITY_IF_THRESHOLD and confidence >= 0.80:
        return "High"

    if src_ip:
        if get_offences(src_ip) >= 2:
            log.debug("Behavioral: %s → High (repeat offender)", src_ip)
            return "High"
        if get_decay_score(src_ip) >= 3.0:
            log.debug("Behavioral: %s → High (persistent, decay=%.2f)", src_ip, get_decay_score(src_ip))
            return "High"

    return "Low"