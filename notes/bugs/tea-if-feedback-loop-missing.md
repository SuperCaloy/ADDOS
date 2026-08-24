---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
tags:
  - backend
  - pipeline
  - tea
  - isolation-forest
  - bug
---

# TEA <-> Isolation Forest Feedback Loop Missing

> [!warning] Clarification (2026-08-23)
> The one-directional flow (IF -> TEA) is **by design**, not a bug. TEA uses IF's per-flow verdict to calibrate what counts as anomalous. This is the correct behavior.
> 
> The real issue is that TEA's own detection output (`is_attack_pattern`) never influences anything downstream because `should_submit()` always returns True. This is documented as **Gap A** in [[bugs/tea-attacks-flagged-as-normal]].
> 
> This note is kept for historical context but should not be treated as a separate bug to fix.

> [!danger] Active bug
> The feedback loop between TEA (temporal entropy analysis) and the Isolation Forest is one-directional. IF tells TEA what is anomalous, but TEA's analysis never influences IF or the worker pipeline.

## Symptom

TEA correctly detects global variance collapse (attack pattern) but this detection has no effect on the ML pipeline's behavior. The system behaves identically whether TEA flags an attack or not. TEA's output is computed but effectively ignored.

## Root Cause Analysis

### The Data Flow (as implemented)

```
zmq_receiver.py
  -> entropy_analyzer.update(dpid, flows)   # TEA runs on aggregate switch data
  -> attaches tea_result to flow_stats      # tea_attack_pattern, tea_confidence, etc.
  -> worker.submit(src_ip, flow_stats, ...)

worker.py
  -> if_pipeline.run_if_inference(if_vec)   # IF scores the individual flow
  -> _tea.feedback(is_anomaly)              # IF verdict -> TEA (lock/unlock baselines)
  -> _result_callback(...)                  # -> decision_engine.on_result()

decision_engine.py
  -> reads flow_stats["tea_attack_pattern"] # TEA result attached by zmq_receiver
  -> entropy_analyzer.should_submit(...)    # TEA mitigation gate
  -> if _tea_mitigate: state_machine.on_detection(...)
```

### Root Cause A: `should_submit()` always returns True

**File:** `backend/pipeline/entropy_analyzer.py:410-420`

```python
def should_submit(self, tea_result: dict, is_flood_prefilter_flagged: bool) -> bool:
    if is_flood_prefilter_flagged:
        return True
    if not tea_result.get("is_learned", False):
        return True
    conf = tea_result.get("confidence", "low")
    if tea_result.get("is_attack_pattern"):
        return True
    if conf == "moderate":
        return True
    return True                          # <-- catches everything
```

Every branch returns True. The method is a no-op. In `decision_engine.py:362`, `_tea_mitigate` is always True, so the TEA mitigation gate never blocks anything. The `if _tea_mitigate:` branch at line 366 always executes, and the `else:` branch at line 407 ("TEA mitigation gate: flash crowd, logging only") never executes.

This was likely intentional at some point (the comment at `zmq_receiver.py:229` says "No pre-ML gate"), but it means TEA's analysis has zero influence on the system.

### Root Cause B: TEA -> IF direction is completely missing

The only connection from TEA to the ML pipeline is `should_submit()`, which always returns True. There is no mechanism for TEA's global analysis to:
- Influence IF's feature extraction or scoring
- Override IF's per-flow verdict
- Adjust IF's threshold
- Flag a flow that IF missed
- Boost priority for flows during a detected attack pattern

TEA detects global variance collapse across all switch flows. IF scores individual flows. These are complementary signals, but TEA's global view never enhances IF's per-flow analysis.

### Root Cause C: `feedback()` is driven by IF's per-flow verdict, not TEA's own analysis

**File:** `backend/pipeline/worker.py:205-210` and `backend/pipeline/entropy_analyzer.py:432-443`

```python
# worker.py:207-208
_tea.feedback(is_anomaly)
```

The `feedback()` method locks baselines when `is_anomaly=True` (IF says this flow is anomalous) and unlocks after 10 consecutive `is_anomaly=False` results. This means:

- TEA's baselines are locked/unlocked based on IF's per-flow verdict
- TEA's own `is_attack_pattern` detection does NOT influence the feedback loop
- If IF classifies most individual flows as normal (e.g., spoofed IPs, low-rate attackers mixed with normal traffic), the feedback latch unlocks even when TEA's global analysis detects a variance collapse

The feedback loop is: IF -> TEA (via `feedback()`), not TEA <-> IF. TEA is a passive recipient of IF's verdict, not an active participant in the detection pipeline.

## Verification Steps

1. **Confirm A:** In `decision_engine.py`, add a log line after `_tea_mitigate = entropy_analyzer.should_submit(...)`. Verify it is always True regardless of TEA's output.

2. **Confirm B:** In `entropy_analyzer.py`, add a counter for how many times `is_attack_pattern=True` in `update()`. Compare with how many times `should_submit()` was called with `is_attack_pattern=True` and returned False. The latter should be zero (it always returns True).

3. **Confirm C:** During an active attack, log both `is_attack_pattern` (TEA's own detection) and the `feedback()` calls (IF's verdict). Check whether there are windows where `is_attack_pattern=True` but `feedback()` receives mostly `is_anomaly=False`, causing the latch to unlock.

## Fix Direction

> [!warning] Do not fix without verifying root causes first. This is an architectural change, not a simple bug fix.

### Option 1: Make `should_submit()` actually gate mitigation

Restore the intended behavior where TEA can block mitigation for flash crowds or low-confidence results. This would make TEA a real gate:
- `is_attack_pattern=True` -> always mitigate
- `confidence=low` AND `not is_flood_prefilter_flagged` -> skip mitigation
- This requires careful tuning to avoid missing real attacks

### Option 2: Feed TEA's global signal into the worker/IF pipeline

Add a mechanism where TEA's `is_attack_pattern` influences the worker:
- When TEA detects a global attack pattern, lower the IF threshold for all flows in that window (boost sensitivity)
- Or: when TEA detects attack pattern, force `is_anomaly=True` for all flows from flagged IPs
- Or: pass TEA features (size_var, intensity_var, z-scores) into IF's feature vector

### Option 3: Use TEA's own analysis in the feedback loop

Change `feedback()` to use TEA's `is_attack_pattern` in addition to (or instead of) IF's per-flow verdict:
- Lock baselines when `is_attack_pattern=True`, regardless of IF's verdict
- Unlock only when `is_attack_pattern=False` for a sustained streak
- This makes TEA self-governing rather than dependent on IF

### Recommended approach

Option 3 is the most surgical. It fixes the feedback loop without changing the mitigation gate or IF's behavior. Options 1 and 2 are larger changes that need more careful testing.

## Related Notes

- [[backend/tea-analysis]]: TEA design and desensitization fix
- [[backend/models]]: IF/RF model details
- [[backend/ml-pipeline]]: full pipeline data flow
- [[bugs/tea-attacks-flagged-as-normal]]: related bug where TEA misses attacks
