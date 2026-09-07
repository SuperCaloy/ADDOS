import logging
from backend.mitigation.behavioral import get_decay_score
from backend.pipeline.flow_tracker import tracker

log = logging.getLogger(__name__)


def get_top_attacker_ips(n: int = 10) -> list[str]:
    """Query ML pipeline for top-N attacker IPs using OR logic.

    Detection triggers if ANY of these are true:
    - IF score > 0.7 (new attacker, no history needed)
    - Decay score > 0.5 (repeat offender, normalized from 0-10 scale)
    - Combined score > 0.5 (both moderate)

    Normal traffic (IF < 0.3 AND decay < 0.2) is explicitly excluded.
    """
    attackers = {}
    for src_ip, entry in tracker._cache.items():
        if not entry.is_valid():
            continue

        decay = get_decay_score(src_ip)
        decay_normalized = min(decay / 10.0, 1.0)

        detect = False

        if entry.if_score > 0.7:
            detect = True

        if decay_normalized > 0.5:
            detect = True

        combined_score = entry.if_score * 0.6 + decay_normalized * 0.4
        if combined_score > 0.5:
            detect = True

        if entry.if_score < 0.3 and decay_normalized < 0.2:
            detect = False

        if detect:
            attackers[src_ip] = combined_score

    sorted_ips = sorted(attackers.keys(), key=lambda x: attackers[x], reverse=True)
    return sorted_ips[:n]
