---
created: 2026-08-24
last-updated: 2026-08-24
status: verified
tags:
  - frontend
  - backend
  - ip-details
  - bug
---

# IP Details Drawer Shows Zero for Reputation Score and Offences Counter

> [!danger] Active bug
> The IP threat analysis drawer displays `0` for both the reputation score and offences counter, even for IPs with known attack history in the database.

## Symptom

When opening the IP details drawer for any attacker IP, the "Reputation" and "Offences" pills always show `0`. The backend has the correct data in `ip_attack_history`, but the frontend never receives it.

## Root Cause

**File:** `backend/api/ip_detail.py`

Both `_build_live_features()` (line 114-124) and `_build_db_features()` (line 290-299) return a `state` dict that includes `ban_level`, `reputation_score`, `first_seen`, and `last_seen`, but **never includes `offence_count`**.

The frontend (`ip-drawer.js:777`) reads `st.offence_count` from the API response:
```javascript
pills.push(['Offences', String(st.offence_count != null ? st.offence_count : 0), 'var(--red,#ff3d5a)']);
```

Since `offence_count` is missing from the API response, `st.offence_count` is `undefined`, and the fallback `0` is displayed.

The `reputation_score` field IS present (from `behavioral.get_decay_score(src_ip)`), but the note title mentions it because users see both pills showing `0` and assume both are broken. In reality, `reputation_score` returns `0` only when there's no attack history in `ip_attack_history` (which is the case for IPs that haven't been through `_clear()` or `manual_release()` yet, since `record_offense()` is only called on those paths).

## Fix

**File:** `backend/api/ip_detail.py`

Added `behavioral.get_offence_count(src_ip)` to both state dicts:

- Line 122: `_build_live_features()` now includes `"offence_count": behavioral.get_offence_count(src_ip)`
- Line 298: `_build_db_features()` now includes `"offence_count": behavioral.get_offence_count(src_ip)`

This calls `writer.get_offense_total_count(src_ip)` which queries `SELECT COUNT(*) FROM ip_attack_history WHERE src_ip = ?`, returning the raw integer count of past offenses.

## Verification

- Syntax check: `ip_detail.py` parses correctly
- Import check: `from backend.api.ip_detail import bp` succeeds
- Import check: `from backend.mitigation.behavioral import get_offence_count` succeeds

## Related Notes

- [[bugs/reputation-scoring-stalled]]: behavioral scoring not increasing during sustained attacks
- [[backend/api]]: REST and SSE API endpoints
- [[backend/mitigation]]: state machine and behavioral reputation design
