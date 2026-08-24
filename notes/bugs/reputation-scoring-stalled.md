---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
tags:
  - backend
  - mitigation
  - behavioral
  - bug
---

# Reputation/Behavioral Scoring Not Increasing

> [!danger] Active bug
> Behavioral reputation scores stay flat or grow too slowly during sustained or repeated attacks. Repeat offenders are not escalating to blackhole as designed.

## Symptom

After an IP is banned, escalated, and released multiple times within a session, `get_offense_count()` (decay score) and `get_offense_total_count()` (raw count) remain at or near zero. `should_blackhole()` never triggers. `assign_priority()` never returns "High" via the repeat-offender or persistent-attacker paths. The IP cycles through Phase 1 quarantine on every re-detection instead of escalating.

## Root Cause Analysis

Three compounding issues, all traced to code in `backend/mitigation/`.

### Root Cause A: `record_offense()` only fires on `_clear()`, not on ban escalation

**File:** `backend/mitigation/state_machine.py`

`record_offense()` writes to `ip_attack_history` in the DB. It is called in exactly two places:

1. `_clear()` at line 648 -- when an IP is released (TTL expired, attack stopped, probation complete).
2. `_advance_to_sinkhole()` at line 541 -- when escalating to sinkhole post-quarantine.

It is NOT called when:
- `_advance_to_ban()` fires (Phase 1 -> Phase 2, line 487)
- `_advance_to_blackhole()` fires (unscored hold -> Phase 3, line 588)
- `on_reoffence()` fires (returning offender detected again, line 664)
- `on_detection()` escalates probation re-attack (line 351)

This means during a sustained attack session where an IP goes through multiple phase transitions (quarantine -> ban -> blackhole), zero rows are written to `ip_attack_history` until the IP is finally cleared. The behavioral DB stays empty throughout the entire session.

**Impact:** `get_offense_count()`, `get_offense_total_count()`, and `get_ban_level()` all query `ip_attack_history`. They return 0 until `_clear()` fires. Within a single long-running attack session, the behavioral scoring system is blind.

### Root Cause B: `should_blackhole()` uses raw count, not decay score

**File:** `backend/mitigation/behavioral.py:94-104`

```python
def should_blackhole(src_ip: str, current_ban_level: int) -> bool:
    offense_score = get_offences(src_ip)       # <-- raw COUNT(*)
    if offense_score >= BLACKHOLE_OFFENSE_THRESHOLD:
        ...
```

`get_offences()` calls `writer.get_offense_total_count()` which is `SELECT COUNT(*)`. The comment on line 98 says "score uses half-life decay" but the code does NOT use decay. The decay function is `get_decay_score()` which calls `writer.get_offense_count()`.

Compare:
- `get_offences()` -> `get_offense_total_count()` -> `SELECT COUNT(*)` -- raw integer count
- `get_decay_score()` -> `get_offense_count()` -> half-life weighted sum (2.0 * 0.5^(hours/24))

The function name, variable name, and comment all say "weighted offense score" but the implementation uses raw count. This is either a bug or a misleading name. Either way, the threshold of 5.0 was designed for decay-weighted scoring (where each offense contributes ~2.0 decaying over time), but raw count means 5 offenses are needed regardless of recency.

### Root Cause C: `on_reoffence()` depends on stale DB state

**File:** `backend/mitigation/state_machine.py:262-400`

In `on_detection()`, the re-offence path is:
1. Line 282: `_prior_ban = behavioral.get_ban_level(src_ip)` -- queries DB
2. Line 284: `if _prior_ban > 0:` -- routes to `on_reoffence()`
3. Line 387-398: post-lock call to `on_reoffence()`

But `get_ban_level()` queries `ip_attack_history` which is only populated by `record_offense()`. Since `record_offense()` only fires on `_clear()` (Root Cause A), an IP that was banned earlier in the same session has `ban_level=0` in the DB. `on_detection()` takes the "new IP" path instead of the "re-offence" path, and the IP goes through Phase 1 quarantine again instead of escalating.

The in-memory `IpState.ban_level` IS incremented by `_advance_to_ban()` (line 498), but this is never checked in `on_detection()` because the code path for existing states (line 348) handles it differently (direct escalation for probation re-attack, but not for Phase 2/3 re-detection).

## Verification Steps

To confirm these root causes before fixing:

1. **Confirm A:** Add a temporary log line at the top of `record_offense()` in `behavioral.py` that logs every call. Run a simulation with repeated attacks. Verify that `record_offense()` is only called when IPs are cleared, not when they are banned or escalated.

2. **Confirm B:** In `should_blackhole()`, add a log line that prints both `get_offences(src_ip)` (raw count) and `get_decay_score(src_ip)` (decay score). Run repeated attacks. Verify they diverge.

3. **Confirm C:** In `on_detection()`, add a log line that prints `_prior_ban` and whether the IP has an in-memory `IpState` with `ban_level > 0`. Run an attack where an IP gets banned, released, and re-detected within the same session. Verify `_prior_ban=0` even though the IP was just banned.

## Fix Direction

> [!warning] Do not fix without verifying root causes first.

### Fix A: Record offense on every phase escalation, not just on clear

Add `behavioral.record_offense()` calls in:
- `_advance_to_ban()` (after line 528)
- `_advance_to_blackhole()` (after line 625)

This writes to `ip_attack_history` at each escalation, so behavioral scoring accumulates during the session.

> [!note] Dedup consideration
> `record_offense()` writes a full row to `ip_attack_history`. If called on every escalation, an IP that goes quarantine -> ban -> blackhole -> clear would generate 3 rows instead of 1. The `offence_count` column should reflect the actual escalation count, not just the terminal count. Alternatively, use `writer.log_attack_history()` with a distinct `event_type` column to distinguish escalations from terminal records. Check whether downstream queries (like `get_offense_total_count`) should count all rows or only terminal records.

### Fix B: Use decay score in `should_blackhole()`

Change `behavioral.py:99` from:
```python
offense_score = get_offences(src_ip)
```
to:
```python
offense_score = get_decay_score(src_ip)
```

This matches the documented intent (half-life decay, threshold 5.0). Verify the threshold still makes sense with decay scoring (a fresh offense contributes 2.0, so 3 recent offenses = 6.0 > 5.0).

### Fix C: Check in-memory state before DB in `on_detection()`

In `on_detection()`, before querying `behavioral.get_ban_level()`, check if the IP already has an in-memory `IpState` with `ban_level > 0`. If so, use that instead of the DB value. This avoids the stale-DB problem for IPs that were banned earlier in the same session.

Alternatively, if Fix A is implemented (recording offenses on escalation), the DB will have current data and this fix may not be needed. But the in-memory check is still faster and more correct for same-session scenarios.

## Fix Verified

- Date: 2026-08-23
- Changes: `behavioral.should_blackhole()` now uses `get_decay_score()`; `_advance_to_ban()` and `_advance_to_blackhole()` record offenses; `manual_release()` preserves `ban_level` and `offence_count`.
- Verification: `scratch/verify_reputation_fix.py` and `scratch/verify_consolidated_fixes.py` both pass.

### Final review fixes (2026-08-23)

- Fixed double increment of `offence_count` in `on_reoffence()` blackhole branches: the two blackhole paths now pass `prev_offence_count` to `IpState` and let `_advance_to_blackhole()` perform the single increment.

## Related Notes

- [[backend/mitigation]]: state machine and behavioral reputation design
- [[backend/models]]: IF threshold and scoring
- [[tasks/tea-desensitization-fix]]: prior fix that touched some of the same code paths
