---
created: 2026-08-24
last-updated: 2026-08-24
status: verified
tags:
  - backend
  - mitigation
  - state-machine
  - bug
---

# Ban Lifecycle Loop: Stale In-Memory State After Expiry

> [!danger] Root cause
> When a time ban expired, `_advance_to_probation()` moved the IP to a Phase 4 Probation state instead of fully releasing it. The IP remained in `state_machine._states` with a stale `ban_level` and no `ttl_expires_at`. Re-detection found the in-memory state and skipped the DB history check in `decision_engine.on_result()`, so `on_reoffence()` was never called. Ban level and reputation scoring stagnated.

## Symptom

Repeat offenders with expired bans were not escalating. An IP banned at level 2, released, then re-detected stayed at level 2 instead of moving to level 3. The behavioral decay score and offense count in `ip_attack_history` did not accumulate across ban cycles.

## Root Cause

`_advance_to_probation()` in `backend/mitigation/state_machine.py` was the handler for ban expiry. It:

1. Set `state.phase = 4` (Probation) with `ttl_expires_at = None`
2. Issued a release command and a `rate_limit` command
3. Deleted the quarantine_state DB row
4. Left the IP in `self._states` (in-memory dict)

On re-detection, `decision_engine.on_result()` checked `prior` from `ip_attack_history`. But the in-memory state was still present, so the code path that calls `state_machine.on_reoffence()` was bypassed. The IP was stuck in a probation state with no escalation path.

Additionally, no offense was recorded in `ip_attack_history` when the ban expired. The `record_offense()` call only existed in `_clear()` (manual release / attack stopped), not in the ban expiry path.

## Fix

Replaced `_advance_to_probation()` with ban-expiry logic that:

1. Calls `behavioral.record_offense()` to persist the completed offense in `ip_attack_history`
2. Logs a mitigation event with `action_taken="Released"` and `event_type="released"`
3. Pushes an SSE event for the dashboard audit log
4. Issues the release command
5. Removes the IP from `self._states` (fully clears in-memory state)
6. Deletes the quarantine_state DB row

After this fix, re-detection finds no in-memory state, queries `ip_attack_history`, sees the prior `ban_level`, and correctly routes through `state_machine.on_reoffence()` with escalating ban levels.

## Dead Code Removal

With Phase 4 Probation no longer entered, all Phase 4 branches became unreachable:

- `tick()` Phase 4 branch
- `update_observation()` Phase 4 branch
- `on_detection()` Phase 4 check
- `_handle_mid_probation_reattack()` method

These were removed in a follow-up commit. The `PROBATION_DURATION` constant and `rate_limit` action references tied to probation observation were also cleaned up where unused.

## Verification

- Offense recording: after a ban expires, `ip_attack_history` contains a new row with `unblock_reason="Ban Expired"`
- Escalation: re-detecting the same IP increments `ban_level` via `on_reoffence()`
- No stale state: `state_machine._states` no longer contains the IP after ban expiry
- Dashboard: SSE event with `event_type="released"` appears in the audit log

## Related Notes

- [[decisions/priority-model-overhaul]]: priority model changes in the same batch
- [[backend/mitigation]]: state machine design
- [[decisions/mitigation-event-logging-strategy]]: event logging context
