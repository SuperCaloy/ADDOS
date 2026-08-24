---
created: 2026-08-24
last-updated: 2026-08-24
status: verified
tags:
  - backend
  - mitigation
  - behavioral
  - priority
  - decision
---

# Priority Model Overhaul: Binary to Weighted Composite

Why `assign_priority()` was replaced from a binary High/Low classifier with a four-tier weighted composite scorer, and the threshold values chosen.

## Problem

The old `assign_priority()` in `backend/mitigation/behavioral.py` returned only "High" or "Low" based on hard cutoffs:

- IF score >= 0.75 AND confidence >= 0.80 -> High
- Repeat offender (2+ offenses) -> High
- Persistent attacker (decay score >= 3.0) -> High
- 3+ prior sinkhole flags -> High
- Everything else -> Low

This binary model had two issues:

1. **No granularity for response scaling.** Phase 1 observation duration, ban duration, and frontend display all depended on priority. With only two tiers, the system could not differentiate between a confirmed SYN flood (urgent) and a borderline ICMP anomaly (watch but don't escalate hard).

2. **Brittle threshold logic.** The conditions were a chain of early-return `if` statements. An IP with IF=0.74 and confidence=0.99 fell to Low despite near-certain attack. The repeat-offender and decay-score checks bypassed the IF/confidence signal entirely.

## Options Considered

**A: More hard cutoffs (add Medium tier with fixed rules).** Rejected: same brittleness problem, just more branches. Does not address the fundamental issue of independent threshold checks ignoring signal combinations.

**B: Weighted composite score (chosen).** Combine IF score, confidence, attack vector severity, traffic volume, and behavioral reputation into a single 0.0-1.0 composite. Map to four tiers via thresholds. Each factor contributes proportionally rather than triggering a binary jump.

**C: Pure ML-based priority (train a classifier).** Rejected: no labeled training data for priority tiers, and the added complexity of a second model was not justified when a transparent formula could capture the same signals.

## Composite Formula

```
base = if_score * confidence

severity = VECTOR_SEVERITY[attack_class]   # SYN=1.0, UDP=0.9, ICMP=0.8, Uncertain=0.5
vector_bonus = (severity - 0.5) * 0.5      # range: 0.0 to 0.25

volume_factor = min(0.15, log10(pps/10) * 0.05)  # range: 0.0 to 0.15, only if pps > 10

reputation_factor = min(0.2, decay_score * 0.02)  # range: 0.0 to 0.2

composite = min(1.0, base + vector_bonus + volume_factor + reputation_factor)
```

Each factor is capped to prevent any single signal from dominating. The `base` term (IF * confidence) carries the most weight for confirmed attacks. The additive bonuses adjust upward for severity, volume, and history.

## Threshold Values

| Tier     | Threshold | Rationale |
|----------|-----------|-----------|
| Critical | >= 0.85   | Near-certain high-severity attack. Shortest observation (5s). |
| High     | >= 0.65   | Confirmed attack or strong signals. Standard observation (20s). |
| Medium   | >= 0.45   | Suspicious but not confirmed. Moderate observation (15s). |
| Low      | < 0.45    | Weak signals. Standard observation (10s). |

Thresholds were chosen to preserve the old High/Low boundary (0.65 approximates the old IF=0.75 * conf=0.80 = 0.60 product) while adding room above and below.

## Attack Vector Severity Weights

| Vector       | Weight | Rationale |
|--------------|--------|-----------|
| SYN Flood    | 1.0    | Most common, highest impact in target network |
| UDP Flood    | 0.9    | High volume, reflection potential |
| ICMP Flood   | 0.8    | Significant but less persistent |
| Uncertain    | 0.5    | No vector classification, neutral contribution |

## Integration Points

- `decision_engine.on_result()` delegates to `behavioral.assign_priority()`, passing `attack_class` and `recent_pps` from flow stats
- `state_machine.on_reoffence()` passes `attack_class` for vector severity weighting
- `state_machine.phase1_duration()` maps priority to observation time: Critical=5s, High=20s, Medium=15s, Low=10s
- TEA fast-track upgrades Low/Medium to High (not Critical) for high-confidence TEA detections
- Frontend color mappings updated for all four tiers

## Behavioral Threshold Change

`BLACKHOLE_OFFENSE_THRESHOLD` raised from 5.0 to 10.0. With the weighted composite providing better per-incident prioritization, the blackhole threshold was increased to require more sustained persistence before triggering direct blackhole escalation. Approximately 5 rapid attacks (each scoring ~2.0 with half-life decay) are now needed instead of 3.

## Related Notes

- [[bugs/ban-lifecycle-loop]]: ban lifecycle fix in the same batch
- [[backend/mitigation]]: state machine and behavioral module
- [[decisions/mitigation-event-logging-strategy]]: event logging context
