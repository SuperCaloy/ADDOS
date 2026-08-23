# Random Forest 0% Accuracy Bug - Root Cause Analysis

## Executive Summary

**Root Cause**: The topology is not successfully populating the ground truth store (`_active_attacks` dict in `backend/api/stats.py`), causing RF accuracy to be `None` (displayed as 0% due to HTML default).

**Status**: Confirmed metrics calculation bug, NOT actual model failure. The RF model is classifying attacks correctly (visible in audit log), but accuracy cannot be computed without ground truth labels.

---

## Evidence

### 1. Database State (Before Manual Intervention)

```sql
-- RF confusion matrix columns: ALL ZERO
SELECT SUM(rf_tp_syn), SUM(rf_tp_icmp), SUM(rf_tp_udp), 
       SUM(rf_syn_as_icmp), SUM(rf_syn_as_udp), ...
FROM traffic_summary;

Result: 0|0|0|0|0|0|0|0|0

-- IF metrics: HAVE DATA
SELECT SUM(if_tp), SUM(if_fp), SUM(if_tn), SUM(if_fn)
FROM traffic_summary;

Result: 185274|0|73566|50926
```

### 2. Ground Truth Store State

```bash
$ curl http://127.0.0.1:5000/api/attack_ground_truth
{}  # EMPTY - no attacker IPs registered
```

### 3. RF Model IS Working (Audit Log)

```sql
SELECT src_ip, attack_class, confidence, timestamp
FROM detection_features WHERE src_ip='10.0.0.6'
ORDER BY id DESC LIMIT 5;

Result:
10.0.0.6|SYN Flood|0.903801|2026-08-23 20:57:50
10.0.0.6|SYN Flood|0.903801|2026-08-23 20:57:50
...
```

The RF model is correctly classifying SYN Flood attacks with 90%+ confidence.

### 4. Manual Test Confirms the Bug

After manually adding ground truth:
```bash
$ curl -X POST http://127.0.0.1:5000/api/attack_ground_truth/start \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.6","attack_type":"SYN"}'

# Wait 2 seconds, then check accuracy:
$ curl http://127.0.0.1:5000/api/model_info
{
  "rf_accuracy": 100.0,  # NOW IT WORKS!
  "if_accuracy": 83.5,
  ...
}
```

---

## Root Cause Chain

### Data Flow Trace

1. **Frontend** (`frontend/static/stats.js:90`):
   ```javascript
   if (info.rf_accuracy != null) 
     set('p-rf', `Classification accuracy: ${info.rf_accuracy.toFixed(1)}%`);
   ```
   - If `rf_accuracy` is `null`, the HTML default "Accuracy: 0%" is displayed

2. **Backend API** (`backend/api/stats.py:78`):
   ```python
   rf_acc = round(correct / rf_total * 100, 1) if rf_total else None
   ```
   - Returns `None` when `rf_total = 0`

3. **Accuracy Computation** (`backend/api/stats.py:64-78`):
   ```python
   rf_rows = query("""
       SELECT SUM(rf_tp_syn) as tp_syn, SUM(rf_tp_icmp) as tp_icmp,
              SUM(rf_tp_udp) as tp_udp,
              SUM(rf_syn_as_icmp) as syn_as_icmp, ...
       FROM traffic_summary
   """)
   correct = tp_syn + tp_icmp + tp_udp
   wrong = syn_as_icmp + syn_as_udp + ...
   rf_total = correct + wrong
   ```
   - All columns are 0, so `rf_total = 0`, so `rf_acc = None`

4. **RF Metrics Writing** (`backend/pipeline/decision_engine.py:479-502`):
   ```python
   if _expected_class and _predicted:
       if _predicted == _expected_class:
           _rf_tp = 1
           ...
       else:
           _rf_fp = 1; _rf_fn = 1
           ...
   ```
   - This block is NEVER entered because `_expected_class` is always `None`

5. **Ground Truth Lookup** (`backend/pipeline/decision_engine.py:457-459`):
   ```python
   from backend.api.stats import get_active_attacks as _get_gt
   _gt = _get_gt()
   _expected_class = _gt.get(src_ip)  # Always returns None
   ```
   - `_gt` is an empty dict `{}`, so `_gt.get(src_ip)` returns `None`

6. **Ground Truth Store** (`backend/api/stats.py:13`):
   ```python
   _active_attacks: dict[str, str] = {}  # ip -> attack_type
   ```
   - This dict is EMPTY because the topology is not successfully calling the API

### Why Topology Is Not Populating Ground Truth

The topology code (`topology/topology.py:480-490`) calls the API:
```python
def _notify_attack_start(ip: str, attack_type: str) -> None:
    try:
        req = urllib.request.Request(
            f"{BACKEND_API}/api/attack_ground_truth/start",
            data=_json.dumps({"ip": ip, "attack_type": attack_type}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception:
        pass  # SILENTLY IGNORES ERRORS
```

**Problem**: Exceptions are caught and silently ignored. If the API call fails (network issue, timing issue, backend not ready), the topology doesn't know, and the ground truth is never populated.

---

## Why IF Accuracy Works But RF Doesn't

### Isolation Forest (IF) - Static Ground Truth

```python
# decision_engine.py:449-454
_is_tp = src_ip in _ATTACKER_IPS      # Hardcoded frozenset
_is_legit = src_ip in _LEGIT_HOST_IPS  # Hardcoded frozenset

_if_tp = 1 if _is_tp    else 0
_if_fp = 1 if _is_legit else 0
```

- Uses **static ground truth** (hardcoded IP sets)
- Always available, no external dependency
- Metrics are always computed

### Random Forest (RF) - Dynamic Ground Truth

```python
# decision_engine.py:457-459
from backend.api.stats import get_active_attacks as _get_gt
_gt = _get_gt()
_expected_class = _gt.get(src_ip)  # Requires API call from topology
```

- Uses **dynamic ground truth** (populated by topology API calls)
- Requires topology to successfully call `/api/attack_ground_truth/start`
- If API calls fail, metrics are never computed

---

## Proposed Fix

### Option 1: Add Logging to Topology (Diagnostic)

Add logging to `_notify_attack_start` and `_notify_attack_stop` to see if/why they're failing:

```python
def _notify_attack_start(ip: str, attack_type: str) -> None:
    try:
        req = urllib.request.Request(
            f"{BACKEND_API}/api/attack_ground_truth/start",
            data=_json.dumps({"ip": ip, "attack_type": attack_type}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
        info(f"Ground truth registered: {ip} -> {attack_type}")
    except Exception as e:
        info(f"Failed to register ground truth for {ip}: {e}")
```

### Option 2: Retry Logic (Robustness)

Add retry logic to handle transient failures:

```python
def _notify_attack_start(ip: str, attack_type: str, retries: int = 3) -> None:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                f"{BACKEND_API}/api/attack_ground_truth/start",
                data=_json.dumps({"ip": ip, "attack_type": attack_type}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
            return  # Success
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.5)  # Wait before retry
            else:
                info(f"Failed to register ground truth for {ip} after {retries} attempts: {e}")
```

### Option 3: Fallback to Static Ground Truth (Quick Fix)

If the dynamic ground truth is not available, fall back to static ground truth (similar to IF):

```python
# decision_engine.py:456-465
# RF ground truth - use live topology-reported attack type
from backend.api.stats import get_active_attacks as _get_gt
_gt = _get_gt()
_expected_class = _gt.get(src_ip)

# Fallback: if ground truth not available, use static attacker IP set
if _expected_class is None and src_ip in _ATTACKER_IPS:
    # Infer attack type from RF prediction (not ideal, but better than nothing)
    _expected_class = _class_map.get(attack_class)

# MIXED is a topology-only label (h19), RF's 3-class model was never
# trained to predict it. Scoring it as FN/FP either way corrupts the
# confusion matrix, so it's excluded from RF ground truth entirely.
if _expected_class == "MIXED":
    _expected_class = None
```

**Warning**: This fallback would make RF accuracy artificially high (it would compare RF predictions against themselves). Only use for debugging.

### Option 4: Fix the Topology API Calls (Recommended)

Investigate why the topology is not successfully calling the API:

1. Check if the backend is ready when the topology starts
2. Add a health check before starting attacks
3. Add retry logic with exponential backoff
4. Log all API call failures

Example:
```python
def _wait_for_backend(timeout: int = 30) -> bool:
    """Wait for backend API to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(f"{BACKEND_API}/api/stats")
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            time.sleep(1)
    return False

def launch_attack(sustained: bool = True) -> None:
    if not _wait_for_backend():
        info("ERROR: Backend not ready, cannot launch attacks")
        return
    
    # Proceed with attacks...
```

---

## Verification Steps

After implementing the fix:

1. **Check ground truth is populated**:
   ```bash
   curl http://127.0.0.1:5000/api/attack_ground_truth
   # Should show attacker IPs
   ```

2. **Check RF metrics are being written**:
   ```bash
   sqlite3 logs/ddos.db "SELECT SUM(rf_tp_syn), SUM(rf_tp_icmp), SUM(rf_tp_udp) FROM traffic_summary;"
   # Should show non-zero values
   ```

3. **Check RF accuracy is displayed**:
   ```bash
   curl http://127.0.0.1:5000/api/model_info | grep rf_accuracy
   # Should show a percentage, not null
   ```

4. **Check dashboard**:
   - Open dashboard in browser
   - Verify "Classification Model: Random Forest - Accuracy: X%" shows a real percentage

---

## Impact

- **Current state**: RF accuracy shows 0% (misleading - model is actually working)
- **After fix**: RF accuracy will show real percentage based on ground truth comparison
- **Risk**: Low - this is a metrics display bug, not a model or mitigation bug
- **Urgency**: Medium - operators cannot assess RF model performance without this fix

---

## Files Affected

1. `topology/topology.py` - Add logging/retry to `_notify_attack_start` and `_notify_attack_stop`
2. `backend/pipeline/decision_engine.py` - Optional: add fallback logic (not recommended)
3. `backend/api/stats.py` - No changes needed (API is working correctly)
4. `frontend/static/stats.js` - No changes needed (frontend logic is correct)
5. `frontend/templates/dashboard.html` - No changes needed (HTML default is fine)

---

## Conclusion

This is a **metrics calculation bug**, not an actual model failure. The RF model is classifying attacks correctly, but the accuracy cannot be computed because the ground truth store is not being populated by the topology. The fix is to ensure the topology successfully calls the ground truth API when attacks start.
