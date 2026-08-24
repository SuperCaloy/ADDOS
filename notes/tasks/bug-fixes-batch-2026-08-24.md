---
created: 2026-08-24
last-updated: 2026-08-24
status: done
area:
  - backend
  - frontend
  - audit-log
  - mitigation
---

# Bug Fixes Batch 2026-08-24

Audit log lifecycle investigation. The frontend audit log does not match the intended detection-to-release lifecycle. Three root causes identified through end-to-end tracing of `decision_engine.py` -> `state_machine.py` -> `writer.py` -> SSE -> `log.js`.

## Intended Lifecycle

| Stage | Expected Behavior |
|-------|-------------------|
| 1. Detection | Create new log entry for the IP |
| 2. Mitigation (phase transitions) | Update the same entry in-place (Quarantine -> Time Ban -> Probation) |
| 3. Release / TTL expiry | Finalize and close the entry |
| 4. Re-attack | Create a new, separate entry (not reuse or overwrite the old one) |

## Actual Behavior

| Stage | What Actually Happens | Status |
|-------|-----------------------|--------|
| 1. Detection | Creates new row | Correct |
| 2. Phase transitions | Creates a NEW row for each transition | Wrong |
| 3. Release / TTL expiry | Written to DB but never pushed via SSE | Wrong |
| 4. Re-attack | Creates new row (accidentally correct, only because every event creates a new row) | Accidentally correct |

## Bugs

### 1. Frontend row key includes timestamp, disabling in-place updates

**File:** `frontend/static/log.js:41`

```javascript
const key = `${ip}|${ev.event_type || 'transition'}|${ev.timestamp || ''}`;
```

The key includes `timestamp`, which is different for every event. The in-place update path (lines 42-53) only triggers for exact duplicate SSE deliveries, not for phase transitions within the same incident.

**Result:** Every phase transition (Quarantine -> Time Ban -> Probation) creates a new row instead of updating the existing one. The audit log shows 3-4 rows per IP where it should show one row that updates.

**Fix direction:** Key the map by `${ip}|${session_id}` where `session_id` is a new backend field that identifies a single mitigation lifecycle (detection through release). All events within the same lifecycle share the same `session_id`. When the IP is released, the session ends. When the IP re-attacks, a new `session_id` is generated.

### 2. "Released" events are not pushed via SSE

**File:** `backend/pipeline/decision_engine.py:542-553`

The SSE event push is only inside `on_result()` when `_tea_mitigate` is True. But `_clear()` (which emits the "released" event) is called from:
- `state_machine.tick()` (TTL expiry, probation complete)
- `state_machine.manual_release()` (operator action)

Neither path calls `_push_sse_event()`. The "released" event is written to the DB via `writer.log_mitigation_event()` but never reaches the live SSE stream.

**Result:** The frontend never sees the release live. The map-clearing code at `log.js:34-38` never executes during a live session. The "Released" row only appears on page reload via `/api/recent_events`.

**Fix direction:** Add `_push_sse_event()` call inside `state_machine._clear()` and `state_machine.manual_release()`, with `event_type: "released"`.

### 3. No session concept exists to distinguish incidents

The backend has no concept of a "mitigation session" or "incident ID". Each event is an independent row in `mitigation_events`. The frontend has to infer session boundaries from event ordering and IP presence.

This is why the original re-attack collapse bug (documented in [[bugs/audit-log-re-attack-update]]) existed and why the fix (timestamp in key) overcorrected.

**Fix direction:** Add a `session_id` field to `mitigation_events` table and `IpState`. Generated when an IP enters Phase 1 (or re-offence). All events within that lifecycle carry the same `session_id`. Emitted in SSE payload. Frontend uses it as the row key.

## Implementation Plan

### Step 1: Add session_id to IpState and mitigation_events

- [x] Add `session_id: str` field to `IpState` dataclass (`state_machine.py`). Generated with `uuid4().hex[:12]` on creation.
- [x] Add `session_id TEXT` column to `mitigation_events` table schema (`database/db.py`).
- [x] Update `writer.log_mitigation_event()` to accept and write `session_id`.
- [x] Update all `log_mitigation_event()` call sites in `state_machine.py` to pass `state.session_id`.
- [x] Update `decision_engine.py` `on_result()` detection event write to pass `session_id` from `ip_state`.

### Step 2: Push "released" events via SSE

- [x] In `state_machine._clear()`, after `writer.log_mitigation_event()`, call `_push_sse_event()` with the release payload including `event_type: "released"` and `session_id`.
- [x] In `state_machine.manual_release()`, after `writer.log_manual_action()`, call `_push_sse_event()` with `event_type: "manual"` and `session_id`.
- [x] Import `_push_sse_event` in `state_machine.py` (already imported in `decision_engine.py`).

### Step 3: Include session_id in SSE payload and recent_events API

- [x] Add `session_id` to the SSE event dict in `decision_engine.py:544-553`.
- [x] Add `session_id` to the `/api/recent_events` query and response in `api/events.py`.
- [x] Ensure backward compatibility: if `session_id` is missing (old rows), frontend falls back to current key logic.

### Step 4: Fix frontend row key to use session_id

- [x] Change `_logRows` key from `${ip}|${event_type}|${timestamp}` to `${session_id}` in `log.js:41`.
- [x] On `event_type === 'released'`, delete the `_logRows` entry for that `session_id` (line 34-38).
- [x] On `event_type === 'manual'` (manual release), same cleanup.
- [x] In-place update: when same `session_id` arrives with different action, update the existing row's HTML and flash.

### Step 5: Dedup fix for SSE release events

- [x] The SSE dedup in `decision_engine.py:183-194` is keyed by `src_ip` with 5s TTL. A release event must bypass this dedup (use `force=True`) so it always reaches the frontend.
- [x] Same for manual release events.

## Verification

- [x] **Phase transition test:** IP goes Quarantine -> Time Ban -> Probation. Audit log shows ONE row that updates in-place through each phase.
- [x] **Release test:** IP is released (TTL expiry or manual). Audit log row flashes/fades to indicate closure. "Released" appears in the action column.
- [x] **Re-attack test:** Same IP attacks again after release. Audit log shows a NEW row (different `session_id`) at the top. Old row remains visible with its final state.
- [x] **Page reload test:** After all the above, reload the page. `/api/recent_events` replays correctly with `session_id` grouping. Rows render in correct order.
- [x] **Dedup test:** Rapid SSE events for the same IP in the same session do not create duplicate rows.
- [x] **Manual action test:** Manual Release and Manual Blackhole from the watchlist both produce correct SSE events and update the audit log.

## Files Changed

- `backend/mitigation/state_machine.py` (session_id on IpState, SSE push in `_clear()` and `manual_release()`)
- `backend/pipeline/decision_engine.py` (session_id in SSE payload, force push for releases)
- `backend/database/writer.py` (session_id column in `log_mitigation_event()`)
- `backend/database/db.py` (schema migration for `session_id` column)
- `backend/api/events.py` (session_id in `/api/recent_events` response)
- `frontend/static/log.js` (row key uses `session_id`, release cleanup)

## Related Notes

- [[bugs/audit-log-re-attack-update]]: the original re-attack collapse bug (verified fixed 2026-08-23, but the fix overcorrected)
- [[decisions/mitigation-event-logging-strategy]]: mitigation event ledger design
- [[tasks/bug-fixes-batch-2026-08-23]]: previous batch that fixed the re-attack collapse
- [[frontend/dashboard]]: dashboard architecture and JS module layout

---

## Topology Rebalancing

### Current Attack Distribution (20 attackers)

| Attack Type | Count | Percentage | Hosts |
|-------------|-------|------------|-------|
| SYN | 10 | 50% | h6, h7, h8, h9, h10, h18, h22, h23, h24, h25 |
| ICMP | 7 | 35% | h11, h12, h13, h14, h15, h26, h27 |
| UDP | 2 | 10% | h16, h17 |
| MIXED | 1 | 5% | h19 (SYN + UDP) |

**Problem:** SYN is disproportionately dominant (50%). UDP is severely underrepresented (10%).

### Proposed Rebalanced Distribution

| Attack Type | Count | Percentage | Hosts |
|-------------|-------|------------|-------|
| SYN | 7 | 35% | h10, h18, h19, h22, h23, h24, h25 |
| ICMP | 7 | 35% | h11, h12, h13, h14, h15, h26, h27 |
| UDP | 6 | 30% | h6, h7, h8, h9, h16, h17 |

**Changes:**
- h6: SYN → UDP (port 53)
- h7: SYN → UDP (port 123)
- h8: SYN → UDP (port 1900)
- h9: SYN → UDP (port 11211)
- h19: MIXED → SYN (port 1900)

### Aggressiveness

All attacks already use `--flood` (maximum rate). No slow/low-intensity attacks to fix.

### Additional Changes

1. **Add UDP/ICMP size diversity** to match `mininet_traffic_gen.py`:
   - UDP sizes: Add 64, 128, 256, 800, 1024 (currently only 512, 1400)
   - ICMP sizes: Add 800, 1024, 1200, 1480 (currently 64-1400, 6 sizes)

2. **Increase ramp-up stagger** from 0.05s to 0.5-2.0s (C2 activation realism, matches generator)

### Why No Spoofing in Live Simulation

The generator (`mininet_traffic_gen.py`) uses spoofing (`-a $ip`) for training data diversity. But live simulation (`topology.py`) cannot use spoofing because:
- ML pipeline tracks per-IP state (`state_machine._states[src_ip]`)
- Quarantine/release actions target specific IPs
- Reputation scoring requires consistent `src_ip` history
- Precision/recall metrics need to match predictions to actual attackers

Spoofing would make ML metrics meaningless.

### Implementation Checklist

- [x] Update `_ATTACKER_VARIANTS` dict: h6-h9 SYN→UDP, h19 MIXED→SYN
- [x] Update `_ATTACKER_START_DELAYS` if needed
- [x] Add UDP size diversity: 64, 128, 256, 800, 1024
- [x] Add ICMP size diversity: 800, 1024, 1200, 1480
- [x] Change stagger delays from 0.05s intervals to 0.5-2.0s random
- [x] Update campaign functions (`start_udp_flood_campaign()`, etc.) to reflect new host assignments
- [x] Verify `_ATTACKER_NUMS` set still correct (no changes needed)
- [x] Test: Run `start_mixed_campaign()` and verify balanced attack types in dashboard


Updates applied to permanent notes: [[bugs/audit-log-re-attack-update]]
### Post-fix update (2026-08-24 Session 2)
The `session_id` keying in `log.js` caused a regression where unmitigated traffic (which does not have a `session_id` in SSE events) fell back to timestamp keying, causing an explosion of new rows. The frontend `_logRows` key has been reverted to `ip`, and the `isRelease` check was correctly implemented to untrack the IP, fulfilling the true intent of Option 3 without the `session_id` side effects.
