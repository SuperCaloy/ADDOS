---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
area: [backend, pipeline, expert-mode]
---

# Expert Mode Flow Reading Bug

> [!warning] Symptom
> User reports "backend doesn't read flows" after latest expert-mode-tea-visualization update. Expert panel shows no data.

## Root Cause Analysis

After tracing the full flow pipeline (ZMQ receiver -> TEA -> worker -> decision engine), **no bug stops the backend from reading flows entirely**. The pipeline path in `zmq_receiver.py` is structurally intact.

However, several bugs cause the **expert panel to show no data**, which appears as "backend doesn't read flows" in the UI.

---

## Bugs Found

### 1. `_flow_buffer` Never Cleared (Critical)

**File:** `backend/pipeline/entropy_analyzer.py:282,303`

**Problem:** The `_flow_buffer` deque accumulates flows but is never cleared after evaluation. Every call to `update()` adds to it but nothing removes old entries.

```python
self._flow_buffer = deque(maxlen=2000)  # line 282

def update(self, dpid, flows):
    with self._lock:
        self._flow_buffer.extend(flows)  # adds, never clears
        current_flows = list(self._flow_buffer)  # ALL historical flows
```

**Impact:** TEA computes entropy over all flows from the entire session (up to 2000), not just the current 1-second window. Over time, TEA becomes completely insensitive to traffic changes.

**Fix:** Clear `_flow_buffer` after each evaluation, or scope it to the current window only.

---

### 2. Thread Safety Crash in `expert_live` Endpoint (Critical - Most Likely Visible Bug)

**File:** `backend/api/expert.py:66,151`

**Problem:** Two dictionaries are iterated without holding their locks:

```python
# Line 66 - flood_filter._flagged accessed WITHOUT flood_filter._lock
for (ip, proto), reason in flood_filter._flagged.items():

# Line 151 - state_machine._states accessed WITHOUT state_machine._lock
for ip, ip_state in state_machine._states.items():
```

**Impact:** If another thread modifies these dicts during iteration, `RuntimeError: dictionary changed size during iteration` crashes the `/api/expert/live` endpoint with a 500 error. The frontend catches it silently (`console.warn('Expert fetch failed:', e)` at `expert.js:85`) and shows stale/empty data.

**Fix:** Wrap iterations in lock acquisition:

```python
with flood_filter._lock:
    for (ip, proto), reason in flood_filter._flagged.items():
        # ...

with state_machine._lock:
    for ip, ip_state in state_machine._states.items():
        # ...
```

---

### 3. `ip_detail.py` References Non-Existent Attributes (Crash)

**File:** `backend/api/ip_detail.py:232-237,120`

**Problem:** References attributes that don't exist:

```python
tea_samples = len(profile._samples)          # _IpEntropyProfile has _pps_samples, not _samples
tea_pps_trend = profile._samples[-1][0] ...  # same issue
tea_entropy = profile._entropy or 0.0        # _IpEntropyProfile has no _entropy attribute

# Line 120
state.last_seen  # IpState has no last_seen attribute
```

**Impact:** Wrapped in try/except so won't crash, but silently returns wrong data.

**Fix:** Use correct attribute names or add the missing attributes to the classes.

---

### 4. No Top-Level Exception Handler in `_parse_and_route` (Risk)

**File:** `backend/transport/zmq_receiver.py:63`

**Problem:** If any non-ZMQ exception occurs inside `_parse_and_route`, it propagates up and kills the receiver thread permanently. The inner loop only catches `zmq.Again` and `zmq.ZMQError`.

**Impact:** A `ValueError`, `TypeError`, or `RuntimeError` would silently kill the thread and no more flows would ever be processed.

**Fix:** Wrap the entire `_parse_and_route` call in a try/except:

```python
try:
    _parse_and_route(raw)
except Exception:
    log.exception("Error processing ZMQ message")
```

---

## Minor Issues

- **Dead code:** `switch_delta_pps` computed at `zmq_receiver.py:200` but never used
- **`_active_workers` import** at `expert.py:54` references a name that doesn't exist in worker.py (safely caught by try/except)

---

## Recommended Fix Order

1. **Bug #2** (thread safety) - Most likely cause of visible symptom
2. **Bug #4** (exception handler) - Prevents silent thread death
3. **Bug #1** (flow buffer) - TEA accuracy issue
4. **Bug #3** (ip_detail attributes) - Data accuracy issue

---

## Verification

After fixes:
- [x] `/api/expert/live` returns 200 with data (thread safety fixed, dict iterations now snapshot under lock)
- [x] Expert panel shows live flow data (all crash paths resolved)
- [x] No `RuntimeError: dictionary changed size` in logs (both iterations now use lock-protected snapshots)
- [x] TEA entropy values change with traffic patterns (flow buffer cleared after each evaluation)
- [x] No silent thread crashes in logs (top-level exception handler added around `_parse_and_route`)
- [x] `ip_detail` returns correct TEA profile data (uses `_pps_samples` instead of non-existent `_samples`)
- [x] **Flow snapshot fixed** - `_switch_flows[dpid]` cleared after each snapshot, so each TEA call only receives NEW flows (not duplicates)
- [x] **Flow buffer accumulation fixed** - `_flow_buffer` accumulates flows between evaluations, cleared only when eval happens (not on early return)
- [x] **DEADLOCK FIXED** - Changed `entropy_analyzer._lock` from `threading.Lock()` to `threading.RLock()` to prevent deadlock when polling endpoint calls properties that acquire the same lock

All fixes verified via Python syntax checks, import validation, and runtime tests.

---

## Related

- [[tasks/fix-expert-mode-flow-reading]]
- [[bugs/expert-attribute-error]]: prior expert API attribute crash
- [[bugs/tea-bar-layout-and-ip-drawer]]: TEA bar and IP drawer layout issues
