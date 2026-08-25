---
created: 2026-08-21
last-updated: 2026-08-21
status: verified
tags:
  - backend
  - database
  - mitigation
  - logging
---

# Mitigation event logging strategy

Why `mitigation_events` became a completed lifecycle ledger with a hybrid
live/history split, and why the alternatives were rejected.

## Problem

The system had three stores with unclear ownership:

| Store | Model | Role before |
|---|---|---|
| mitigation_events | append-only INSERT | noisy partial event log |
| quarantine_state | mutable UPSERT, deleted at end | crash recovery only |
| ip_attack_history | append-only per offense session | closed-session summary |

Gaps: no state-machine start events (prefilter quarantine, hold_ip invisible),
per-flow duplicate noise (~1 row/10s during attacks from decision_engine), no
terminal events at all (`_clear()` reasons never reached the log), sinkhole
releases unlogged in DB. The dashboard replay inherited every gap: IPs went to
"Probation" then silently vanished from the event stream.

## Options considered

**A: Single mutable record** (one row per episode, UPDATE in place). Rejected:
destroys audit history; report.py and ip_detail.py already build timelines
from multiple rows; concurrent UPDATE contention; restart restore needs
mutable state somewhere anyway.

**B: Pure append-only log, live status derived by query.** Rejected as sole
mechanism: "currently mitigating at a glance" becomes GROUP BY aggregation per
dashboard poll on a growing table; live fields (time_in_phase_sec,
ttl_remaining_sec) come from monotonic clocks and cannot be faithfully derived
from wall-clock rows.

**C: Hybrid (chosen).** Formalize what existed: live status stays in-memory
(`state_machine` + deception dicts via `/api/quarantine_list`, real-time,
monotonic-clock accurate); `mitigation_events` becomes the complete permanent
event stream; `ip_attack_history` keeps its closed-session role.

## Schema decision: C2 plus reason column

Two additive columns instead of encoding meaning in strings:

- `event_type TEXT DEFAULT 'transition'`: detected | transition | released |
  manual.
- `reason TEXT NULL`: machine-readable release/hold cause ("Attack Stopped",
  "Blackhole TTL Expired", "Probation Complete", "traffic stopped", ...).

Adopted from an earlier same-day session's task note after reconciliation;
cleaner filtering for reports than string-matching action_taken.

## Detection row granularity

One `detected` row per phase entry (not per session): each phase entry carries
fresh detection_ms/mitigation_ms context, and latency metrics stay meaningful.
The earlier per-session idea was superseded by user decision later the same
day. Per-flow repeats are suppressed by a `_should_log_detection(src_ip,
phase_entered)` gate in decision_engine keyed on the monotonic phase-entry
timestamp; writer dedup cache kept untouched as a safety net.

## Deferred (known gaps, intentionally not fixed here)

- Probation entries delete their quarantine_state row while still actively
  managed; sinkhole entries are memory-only. Restarts silently drop watched
  IPs. Tracked in [[known-issues/known-issues]].
- Archive table lacks latency columns (pre-existing, impact nil).

## Related notes

- [[tasks/mitigation-event-logging]]: implementation record.
- [[backend/database]], [[backend/mitigation]]: how it works now.
