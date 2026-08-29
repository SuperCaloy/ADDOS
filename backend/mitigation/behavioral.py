import logging
import math
from backend.database import writer

log = logging.getLogger(__name__)

# ── Thresholds ─────────────────────────────────────────────────────────────
# Weighted offense score triggering direct blackhole (half-life decay, 24h). 5 rapid attacks accumulate to 10.0.
BLACKHOLE_OFFENSE_THRESHOLD = 10.0

# Attack vector severity weights (higher = more severe)
VECTOR_SEVERITY = {
    "SYN Flood":  1.0,
    "ICMP Flood": 0.8,
    "UDP Flood":  0.9,
    "Uncertain":  0.5,
}

# Priority tier thresholds (composite severity score)
PRIORITY_CRITICAL_THRESHOLD = 0.85
PRIORITY_HIGH_THRESHOLD     = 0.65
PRIORITY_MEDIUM_THRESHOLD   = 0.45


def record_offense(src_ip: str, attack_vector: str, if_score: float,
                   confidence: float, priority: str,
                   phase_reached: int, first_seen: str,
                   unblock_reason: str = "Auto-Released",
                   ban_level: int = 0, offence_count: int = 1) -> None:
    # Writes completed offense to ip_attack_history; called on release so history persists across restarts.
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
        log.debug("Behavioral: offense recorded - %s  vector=%s  phase=%d",
                  src_ip, attack_vector, phase_reached)
    except Exception as exc:
        log.warning("Behavioral: failed to record offense for %s - %s", src_ip, exc)


def get_decay_score(src_ip: str) -> float:
    # Reuses writer.get_offense_count (half-life decay). Fresh ~2.0, 24h ago ~1.0, 48h ago ~0.5.
    try:
        return writer.get_offense_count(src_ip)
    except Exception as exc:
        log.warning("Behavioral: decay score failed for %s - %s", src_ip, exc)
        return 0.0


def get_offence_count(src_ip: str) -> int:
    # Raw count of how many times this IP has offended.
    try:
        count = writer.get_offense_total_count(src_ip)
        return count if count is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get offence count for %s - %s", src_ip, exc)
        return 0


def get_offences(src_ip: str) -> int:
    # Queries total offense count from ip_attack_history; returns 0 on no history or DB error.
    try:
        count = writer.get_offense_total_count(src_ip)
        return count if count is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get offenses for %s - %s", src_ip, exc)
        return 0


def get_ban_level(src_ip: str) -> int:
    # Queries last recorded ban level from DB; returns 0 if no history.
    try:
        level = writer.get_ban_level(src_ip)
        return level if level is not None else 0
    except Exception as exc:
        log.warning("Behavioral: failed to get ban level for %s - %s", src_ip, exc)
        return 0


def is_known_offender(src_ip: str) -> bool:
    # True if the IP has any prior offense; used to route returning attackers via on_reoffence().
    return get_offences(src_ip) > 0


def should_blackhole(src_ip: str, current_ban_level: int) -> bool:
    # Returns True if the IP should skip ban escalation and go straight to blackhole.
    # Triggers on a persistent offender whose decayed offense score meets the threshold.
    offense_score = get_decay_score(src_ip)
    if offense_score >= BLACKHOLE_OFFENSE_THRESHOLD:
        log.info("Behavioral: %s decay_score=%.2f >= %.1f -> blackhole",
                 src_ip, offense_score, BLACKHOLE_OFFENSE_THRESHOLD)
        return True
    return False


def assign_priority(if_score: float, confidence: float, src_ip: str = "",
                    attack_class: str = "Uncertain",
                    recent_pps: float = 0.0) -> str:
    base = if_score * confidence

    severity = VECTOR_SEVERITY.get(attack_class, 0.5)
    vector_bonus = (severity - 0.5) * 0.5

    volume_factor = 0.0
    if recent_pps > 10:
        volume_factor = min(0.15, math.log10(recent_pps / 10) * 0.05)

    reputation_factor = 0.0
    if src_ip:
        decay = get_decay_score(src_ip)
        reputation_factor = min(0.2, decay * 0.02)

    composite = min(1.0, base + vector_bonus + volume_factor + reputation_factor)

    if composite >= PRIORITY_CRITICAL_THRESHOLD:
        return "Critical"
    if composite >= PRIORITY_HIGH_THRESHOLD:
        return "High"
    if composite >= PRIORITY_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"