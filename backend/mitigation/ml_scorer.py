# Machine learning scoring helper for attacker ranking and triage.
# Evaluates active flow tracker entries against behavioral and anomaly thresholds.

import logging
from backend.mitigation.behavioral import get_decay_score
from backend.pipeline.flow_tracker import tracker

log = logging.getLogger(__name__)


def get_top_attacker_ips(n: int = 10) -> list[str]:
    # Identifies the highest-risk attacking IPs based on Isolation Forest and behavioral decay scores.
    # Returns up to n sorted IP addresses prioritized for mitigation enforcement.
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
