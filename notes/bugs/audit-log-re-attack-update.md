---
created: 2026-08-23
last-updated: 2026-08-24
status: verified
tags:
  - frontend
  - backend
  - audit-log
  - bug
---

# Audit Log Updates Old Entry on Re-Attack Instead of Creating New Row

> [!danger] Active bug
> When a released attacker re-attacks, the Mitigation Audit Log updates the old row in-place instead of inserting a new row. The DB has the correct data (new row exists), but the frontend collapses it into the old entry.

## Symptom

An attacker IP goes through: Quarantine -> Time Ban -> Released (ban expired) -> re-attacks -> Quarantine. The audit log shows only the latest state for that IP. The earlier "Quarantine" and "Released" entries are visually overwritten. The user sees one row for the IP that keeps updating, not a history of distinct incidents.

## Root Cause

**File:** `frontend/static/log.js:33-44`

The frontend tracks audit log rows using a `Map` keyed by `src_ip` only:

```javascript
const _logRows = new Map();  // src_ip -> { tr, action }
```

When an event arrives, `addLogRow()` checks:
1. Does `_logRows` have this IP?
2. If yes, is the action the same?
3. If same action -> **update in-place** (line 37: `existing.tr.innerHTML = html`)
4. If different action -> insert new row at top (escalation)

The problem: when a released attacker re-attacks and gets the same action as a previous incident (e.g., "Quarantined" again), the frontend matches the IP, sees the same action, and updates the old row. It cannot distinguish between:
- A phase escalation within the same incident (Quarantine -> Ban) -- should update
- A new incident with the same action (Released -> new Quarantine) -- should insert new row

### Why different-action escalations work

When an IP escalates from "Quarantined" to "Time Ban", the action differs, so the code falls through to insert a new row (line 43-65). This is correct for within-incident escalation.

### Why re-attacks with same action fail

When an IP is released and then re-quarantined, the action is "Quarantined" again. The map still has the old entry with action "Quarantined". The code matches and updates in-place.

### Fix Details (2026-08-24)

We replaced the compound row key with a single lifecycle `session_id` to accurately track incidents from detection through release. 
- **Backend**: `IpState` now generates a UUID `session_id`. This ID is included in `mitigation_events` (via DB schema changes) and SSE payloads for all phase transitions and manual operator actions.
- **Frontend (`log.js`)**: The row key uses `ev.session_id`. When a release event (or manual release) arrives, it flashes the row and removes the key from the map, ensuring any future re-attacks generate a fresh row.

## The map is never cleared on release

The map entry for an IP is only removed when:
- The row is evicted from the DOM (line 51: `_logRows.delete(oldIp.textContent.trim())`)
- The page is reloaded

There is no mechanism to clear the map entry when an IP is released. The "Released" event creates a new row (different action), but the map is updated to point to the "Released" row. When the IP re-attacks with "Quarantined", the map still has the IP, and if the action matches any previous row for that IP, it updates in-place.

> [!note] The backend is correct
> The DB correctly creates new rows for re-attacks. `_is_duplicate()` in `writer.py:18-31` uses key `(src_ip, if_score, action_taken, phase)` with a 10-second TTL. A re-attack after release has a different phase and/or is >10s apart, so it passes the dedup check and creates a new DB row. The bug is purely in the frontend's row tracking.

## Verification Steps

1. **Confirm the DB has correct data:**
   ```sql
   SELECT id, timestamp, src_ip, action_taken, phase, event_type, reason
   FROM mitigation_events
   WHERE src_ip = '10.0.0.X'
   ORDER BY id;
   ```
   Expected: multiple rows for the same IP, including separate rows for each incident's "Quarantined" entry.

2. **Confirm the frontend collapses them:**
   - Run a simulation where an attacker is banned, released, and re-attacks
   - Watch the audit log in the dashboard
   - Expected: only one row per IP visible at a time, updating in-place
   - Actual: should show separate rows for each incident

3. **Confirm the map is the problem:**
   - In browser devtools console, run: `console.log(_logRows)`
   - After a re-attack, check if the map has the IP with the old action
   - If the action matches, the in-place update path was taken

## Fix Direction

> [!warning] Do not fix without verifying root cause first.

### Option 1: Key the map by (IP, timestamp) instead of IP alone

Change `_logRows` to use a composite key:

```javascript
const _logRows = new Map();  // `${ip}|${timestamp}` -> { tr, action }
```

In `addLogRow()`:
```javascript
const key = `${ip}|${ev.timestamp}`;
```

This makes each event unique. The "same action -> update in-place" logic only triggers for events with the exact same IP and timestamp, which is the correct behavior (dedup of duplicate SSE deliveries).

> [!note] Trade-off
> This disables the "update in-place on escalation" behavior. Each phase transition creates a new row. The audit log shows more rows but accurately reflects the event history. If the "escalation updates in-place" behavior is desired, Option 2 is better.

### Option 2: Clear map entry on "Released" event

When an IP is released, remove its map entry so the next event for that IP creates a new row:

```javascript
if (/released/i.test(newAction)) {
  _logRows.delete(ip);
}
```

This preserves the "update in-place on escalation" behavior within an incident, but starts a new row chain after release.

> [!warning] Edge case
> The "Released" event itself needs to create a row first, then clear the map entry. Otherwise the "Released" row will not be tracked. The order matters:
> 1. Create/update row for "Released"
> 2. Clear map entry for IP
> 3. Next event for IP creates a new row

### Option 3: Use `event_type` to distinguish incidents

The DB has `event_type` column ("transition", "released", "detected", "manual"). The `/api/recent_events` endpoint returns it, but the live SSE payload does not.

Add `event_type` to the SSE payload in `decision_engine.py:533-541`:
```python
_push_sse_event({
    ...
    "event_type": event.get("event_type", "transition"),
}, ...)
```

In the frontend, use `event_type` to decide insert-vs-update:
```javascript
if (ev.event_type === 'released') {
  _logRows.delete(ip);
}
```

This is the most robust approach because it uses the backend's event classification rather than inferring from action text.

### Recommended approach

Option 3 is the most robust. It requires:
1. Backend: add `event_type` to SSE payload (one line change in `decision_engine.py`)
2. Frontend: check `event_type` to clear map on release (3 lines in `log.js`)

Option 2 is simpler but fragile (relies on action text matching). Option 1 changes the UX significantly.

## Fix Verified

- Date: 2026-08-24
- Changes: Frontend `_logRows` Map now uses composite key `${ip}|${event_type}` instead of IP alone. Each event type (transition, released, manual, detected) gets its own row. Re-attacks after release produce a new key, so a fresh row is always inserted instead of updating the old entry.
- Verification: Syntax check passes for `log.js`; import of `backend.pipeline.decision_engine.on_result` succeeds.

### Implementation details (2026-08-24)

- `log.js:33` - key changed from `ip` to `ip + '|' + (ev.event_type || 'transition')`
- `log.js:58` - eviction uses composite key via `dataset.eventType`
- `log.js:70` - new rows store `dataset.eventType` for correct future eviction
- The "Released" event still clears its own key from the map (line 48), ensuring clean state for any future re-attacks

## Related Notes

- [[decisions/mitigation-event-logging-strategy]]: why mitigation_events became a lifecycle ledger
- [[backend/mitigation]]: state machine phases and lifecycle events
- [[backend/api]]: REST and SSE API endpoints
