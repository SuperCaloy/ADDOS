---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
area: [frontend, backend, ui-ux]
tags:
  - bugs
  - tea-visualization
  - ip-drawer
  - flow-tracker
---

# TEA Bar Layout and IP Drawer Bugs

> [!note]
> Session 2026-08-23. Two TEA bar UI fixes completed. Two IP drawer bugs investigated with root causes identified; fixes pending.

---

## Fix 1: TEA Z-Score Bar Overlapping Elements

**File:** `frontend/static/style.css`, `frontend/static/expert.js`

**Problem:** The z-score bar elements (threshold marker dot, vertical line, value label like "+51.2z") were all bunched together in nearly the same spot, making the bar hard to read.

**Fix:** Moved the value label out of the header row and positioned it absolutely above the track, aligned with the fill end point. Each element now has its own vertical space:
- Header row: metric name + raw value only
- Above track: z-score badge (floating, follows the fill)
- On track: midline (center), threshold marker (at sigma), fill bar

**CSS changes:**
- `.zscore-header` changed from `justify-content: space-between` to `justify-content: flex-start`
- `.zscore-num` repositioned with `position: absolute; top: -20px; transform: translateX(-50%)`
- `.zscore-track` given `margin-top: 8px` for breathing room
- Threshold marker dot enlarged and given `border: 2px solid var(--surface)` for separation from the line

**JS changes:**
- `.zscore-num` moved from `.zscore-header` into `.zscore-track` with `style="left: ${pct}%"`
- Real-time updates (poll + SSE) now update both text and `left` position of the label

---

## Fix 2: TEA Bar Bounded Behavior (Match IF Bar)

**File:** `frontend/static/style.css`, `frontend/static/expert.js`

**Problem:** The TEA bars did not behave like the IF bar. For high z-scores (+41.4z, +26.6z), the fill and value label pushed past the bar edges, always looking maxed out or overflowing. The IF bar keeps its fill and marker bounded within the track regardless of value.

**Root cause:** Two issues:
1. `.zscore-track` had `overflow: visible`, allowing the fill to visually escape the track bounds
2. The floating `.zscore-num` badge was positioned at the fill end with no clamping, so it overflowed the bar for high values

**Fix:** Matched the IF bar pattern exactly:
- Changed `.zscore-track` from `overflow: visible` to `overflow: hidden` so fill/marker never escape
- Removed the floating `.zscore-num` badge entirely
- Added `.zscore-stats` row below each track (same pattern as `.if-stats`), showing "Z-score: +41.4z" and "Threshold: 2.5sigma" as text
- Threshold marker now uses `transform: translateX(-50%)` (same as IF bar) instead of a separate dot pseudo-element

**Result:** TEA bars now match IF bar behavior: track stays bounded, values shown as text below. Fill width is already clamped to 0-100% in JS, so with `overflow: hidden` it stays within bounds.

---

## Bug 3: IP Drawer Shows All Zeros for Active IP

**File:** `backend/api/ip_detail.py`, `backend/pipeline/flow_tracker.py`

**Symptom:** For IP 10.0.0.24, every feature value (Flow Rate, Byte Rate, Pkt Size Uniformity, Packet Count, all IF 16-features, all RF 15-features) shows 0 / 0.0000, even though the same record shows a real IF score (0.6461), RF confidence (92.9%), and SYN Flood classification.

**Root cause:** `tracker.update_flow()` is defined in `backend/pipeline/flow_tracker.py:56` but is **never called anywhere in the codebase**. This means `tracker._flows` is always empty, so `tracker.get_flow(src_ip)` always returns `None`.

In `ip_detail.py:_build_live_features()`:
```python
flow   = tracker.get_flow(src_ip)   # Always None
cached = tracker.get_cached(src_ip) # May have data from worker
if not flow or not cached:
    return None  # Returns None because flow is None
```

When `_build_live_features` returns `None`, the endpoint falls through to `_build_db_features()`, which queries the `detection_features` table. If no row exists for this IP (e.g., IP was flagged via flood prefilter path which bypasses the worker), all feature values are zero.

The IF score and RF confidence come from the inference cache (`cached.if_score`) or the `mitigation_events` DB table, which is why those show real values while features show zeros.

**Fix needed:** Call `tracker.update_flow(src_ip, flow_stats)` somewhere in the pipeline. The natural place is in `decision_engine.on_result()` or in the worker's `_process_item()` before/after inference. Alternatively, populate `_flows` from the ZMQ receiver when flows arrive.

---

## Bug 4: "HISTORICAL" Label Shown During Active Mitigation

**File:** `backend/api/ip_detail.py`, `frontend/static/ip-drawer.js`

**Symptom:** The drawer shows "ACTION: Quarantined" (an active mitigation state) but tags the record as "HISTORICAL" at the top. "Historical" should only apply once mitigation has fully concluded (released, expired, or cleared).

**Root cause:** Same as Bug 3. Since `tracker.get_flow()` always returns `None`, `_build_live_features()` returns `None`, and the endpoint falls through to `_build_db_features()` which sets `"is_live": False`.

In `ip-drawer.js:_setBadge()`:
```javascript
function _setBadge(isLive) {
  if (isLive) { /* shows "LIVE" badge */ }
  else { /* shows "HISTORICAL" badge */ }
}
```

The `is_live` flag comes from the API response. Since the live path fails, `is_live` is always `False`, so the badge always shows "HISTORICAL" even for actively mitigated IPs.

**Fix needed:** Same as Bug 3. Once `tracker.update_flow()` is called properly, `_build_live_features()` will succeed for active IPs, returning `"is_live": True`, and the badge will show "LIVE".

Additionally, the `_is_active()` check in `ip_detail.py` already correctly identifies active IPs via `state_machine._states`, so the routing logic is fine. The problem is purely that the live data builder fails due to the missing flow tracker update.

---

## Summary

| Issue | Status | Root Cause |
|-------|--------|------------|
| TEA bar overlapping elements | Fixed | Label positioned in header row, colliding with threshold marker |
| TEA bar unbounded fill/label | Fixed | `overflow: visible` + floating label with no clamping |
| IP drawer all zeros | Fixed | `tracker.update_flow()` never called, `get_flow()` always returns None |
| IP drawer HISTORICAL label | Fixed | Live path fails, falls back to DB. Also fixed SQL error with non-existent `last_seen` column in fallback |

---

## Related

- [[bugs/expert-mode-flow-reading-bug]] - Previous session's IP detail attribute errors
- [[tasks/expert-mode-tea-visualization-plan]] - Original TEA visualization implementation plan
