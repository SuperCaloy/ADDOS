---
created: 2026-08-21
last-updated: 2026-08-21
status: done
area: [backend, database]
---

# Mitigation event logging overhaul

Goal: hybrid logging per approved analysis. Live view stays served from
in-memory `_states`; `mitigation_events` becomes a complete append-only
lifecycle ledger (one row per meaningful event, with `event_type` + `reason`
columns); per-flow-result noise from `decision_engine.on_result` is reduced to
a single `detected` row per phase entry; `_clear()` finally emits terminal
`released` events; archiver mirrors the new columns.

Decisions locked with user 2026-08-21:
- First detection per phase entry only (decision_engine stops spamming rows;
  per-session was the earlier idea, superseded same day).
- Dedicated `reason TEXT` column alongside `event_type` (not string encoding).
- Live "currently mitigating" view stays served from memory (quarantine_state
  remains recovery-only).
- Event vocabulary: detected | transition | released | manual.
- Additive API passthrough of the new fields in recent_events and ip_detail.
- Restart durability for probation/sinkhole entries: DEFERRED, see
  [[known-issues/known-issues]].
- No git commands during this task.

Checklist:

- [x] Task 1: schema + migration + writer event_type/reason support
      (db.py CREATE TABLE x2 + idempotent ALTERs; writer INSERT extended;
      log_manual_action writes event_type='manual'; migration smoke test
      passed on fresh + legacy DBs, twice each)
- [x] Task 2: state machine owns transition events, `_clear()` released events
      (prefilter trip start row; hold_ip start row; high-priority immediate
      Time Ban transition row, a pre-existing gap found by the driver;
      _clear emits released rows with reason for all three auto-release paths)
- [x] Task 3: decision_engine first-per-phase-entry gate (`_should_log_detection`
      keyed on monotonic phase_entered, cap-128 prune), force_insert removed,
      detection rows tagged event_type='detected'
- [x] Task 4: deception sinkhole transition tag + released rows in
      _evaluate release branch, emergency_clear_one (manual release) and
      emergency_clear (resource guard CRIT); duplicate `_release_callback`
      call deleted as isolated sub-step (idempotent: callback is log-only)
- [x] Task 5: archiver mirrors new columns; additive passthrough in
      recent_events and ip_detail phase history
- [x] Task 6: REQUIRED lifecycle driver run, ALL ASSERTIONS PASSED, evidence
      table pasted to user (14 rows across scenarios A-F incl. churn-return
      re-detection and gate repeat-suppression)
- [x] Task 7: notes finalized ([[decisions/mitigation-event-logging-strategy]],
      [[backend/database]], [[backend/mitigation]], [[backend/api]] touched
      lightly, known-issues updated)

Decision record: [[decisions/mitigation-event-logging-strategy]]

Issues found and fixed during implementation:
- High-priority immediate Time Ban path never wrote any mitigation_events row
  (only Python logging). Driver scenario F exposed it; transition row added.
- `deception.py` duplicated `_release_callback(src_ip)` invocation removed.

Known unrelated issues spotted during analysis (flagged, not fixed):
- `mitigation_events_archive` lacks detection_ms/mitigation_ms columns
  (pre-existing; latency metrics only query hot table, so impact is nil).
- `state_machine.py` on_reoffence phase string contains a pre-existing
  em-dash ("Phase 1 — Re-offence #N"); left untouched (surgical change rule).
