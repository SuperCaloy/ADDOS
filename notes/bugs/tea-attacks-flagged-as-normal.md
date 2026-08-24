---
created: 2026-08-23
last-updated: 2026-08-24
status: verified
tags:
  - backend
  - pipeline
  - tea
  - bug
---

# TEA Still Flags Real Attacks as Normal

> [!warning] Possible regression or incomplete fix
> The desensitization fix from [[tasks/tea-desensitization-fix]] (2026-08-21) is present in the code and verified by `scratch/verify_tea_fix.py`. However, some attacks are still getting through unflagged. This note documents what was checked, what is present, and what gaps remain.

## Resolution Status

Most gaps documented below were addressed in the Task 2 fix on 2026-08-23. See [[backend/tea-analysis]] for implementation details.

- **Fixed:** Gap A (`should_submit()` now gates), Gap B (AND relaxed to OR with differentiated confidence), Gap C (dynamic sigma capped lower), Gap F (learning phase reduced from 30 to 15), plus a new third dimension `proto_entropy`.
- **Not fixed:** Gap D (aggregate dilution) and Gap E (Phase 2/3 TEA skip) remain by design or require broader architecture changes.

## How TEA Is Supposed to Work

Based on the design:
1. TEA and Flood Prefilter are **gates** that sit before IF
2. Traffic flows: `Traffic -> [Flood Prefilter] -> [TEA] -> IF -> Mitigation`
3. TEA analyzes network packets and classifies them as normal or anomalous
4. TEA learns from IF's feedback (IF -> TEA via `feedback()`)
5. When TEA flags something (high confidence attack pattern), it gates to IF
6. When TEA is uncertain or confident it's normal (flash crowd), it blocks the gate
7. IF classifies what gets through the gates, TEA learns from IF's output

The implementation now uses a three-dimensional OR gate and a functional `should_submit()` gate, so TEA's verdict influences whether traffic is submitted to IF.

## Status of the Prior Fix

The desensitization fix from [[tasks/tea-desensitization-fix]] addressed three root causes:
1. Per-flow lock flapping (one normal flow unlocking baselines)
2. Baselines learning from attack windows
3. Robust reject too weak against slow drift

### What is present in the current code

All three parts of the fix are present and correctly implemented:

**1. observe/learn split** -- `backend/pipeline/entropy_analyzer.py:154-163`
- `_GlobalEntropyState.observe()` appends to window only (line 154)
- `_GlobalEntropyState.learn()` pushes both baselines (line 157)
- `_GlobalEntropyState.push()` calls both (line 161, kept for API compat)

**2. Conditional learning in `update()`** -- `backend/pipeline/entropy_analyzer.py:262-408`
- Line 318: `state.observe(snapshot)` -- unconditional observation
- Line 325: `state.learn(snapshot)` -- only when `not state.is_ready()` (initial learning phase)
- Line 352: `state.learn(snapshot)` -- only when `not is_learned` (still in learning phase)
- Line 361-363: `if not is_attack_pattern: state.learn(snapshot)` -- freeze during attack

**3. Latched feedback** -- `backend/pipeline/entropy_analyzer.py:432-443`
- `feedback(is_anomaly=True)` locks both baselines immediately
- `feedback(is_anomaly=False)` increments streak counter
- Unlock requires `TEA_FEEDBACK_UNLOCK_STREAK = 10` consecutive normal results

**4. Worker calls the latch** -- `backend/pipeline/worker.py:206-210`
- `_tea.feedback(is_anomaly)` replaces the old `confirm_attack()`/`confirm_normal()` pair

> [!note] The fix is present and verified
> `scratch/verify_tea_fix.py` confirms: attack pattern holds for 80 consecutive windows, baselines never drift during attack, recovery after attack ends. The specific bug from the task (sustained flood causing TEA to flip to normal after 10-30s) is fixed.

## Remaining Gaps: Why Some Attacks Still Get Through

The prior fix solved the baseline drift problem. But there are other paths where attacks are not flagged.

### Gap A: `should_submit()` always returns True, so TEA's output has no effect

**File:** `backend/pipeline/entropy_analyzer.py:410-420`

```python
def should_submit(self, tea_result, is_flood_prefilter_flagged):
    ...
    return True    # every branch returns True
```

Even when TEA correctly identifies `is_attack_pattern=True`, the result is the same as when it doesn't. The mitigation gate in `decision_engine.py:362` (`_tea_mitigate`) is always True. TEA's detection has no influence on whether mitigation happens.

This is documented separately in [[bugs/tea-if-feedback-loop-missing]]. It means TEA can be perfectly detecting attacks and the system would behave identically to TEA not existing at all.

### Gap B: Attack detection requires BOTH size AND intensity variance to collapse

**File:** `backend/pipeline/entropy_analyzer.py:358`

```python
is_attack_pattern = size_collapsed and intensity_collapsed
```

If only one dimension collapses, the result is `confidence="moderate"` but `is_attack_pattern=False`. Some attacks may only affect one dimension:

- **Pure UDP flood with varied packet sizes**: intensity variance collapses (uniform flow rates) but size variance may not (varied payload sizes). TEA reports "moderate" but not "attack".
- **Low-rate application-layer attack**: neither dimension collapses significantly. TEA reports "low" confidence.
- **ICMP flood with varied sizes**: size variance may remain high if echo payloads vary.

### Gap C: Dynamic attack sigma scales up with coefficient of variation

**File:** `backend/pipeline/entropy_analyzer.py:121-126`

```python
def dynamic_attack_sigma(self) -> float:
    cv = self._std / (abs(self._mean) + 1e-9)
    sigma = TEA_ATTACK_SIGMA + cv * 1.5
    return max(2.0, min(3.5, sigma))
```

When the baseline has high CV (variable normal traffic), `attack_sigma` increases up to 3.5. This means the variance must drop further below the mean to be flagged. In networks with naturally variable traffic, this makes detection harder.

The base threshold is `TEA_ATTACK_SIGMA = 2.5` (line 21). With CV=1.0 (std equals mean), sigma jumps to 4.0, clamped to 3.5. The z-score must be <= -3.5 instead of -2.5. That is a 40% higher bar.

### Gap D: TEA only sees aggregate switch data, not per-IP data

**File:** `backend/transport/zmq_receiver.py:227`

```python
tea_result = entropy_analyzer.update(dpid, switch_flow_list)
```

TEA runs on ALL flows for a switch, producing a single global result. This result is then attached to ONE flow's `flow_stats` (the current one being processed in `_process_flow_stats`). Other flows from the same poll cycle may get the cached result (due to the 1-second throttle at `entropy_analyzer.py:267-268`), but flows processed in different poll cycles get independent results.

If an attacker's flows are a small fraction of the switch's total traffic, the aggregate variance may not collapse enough to trigger detection. TEA's global view is a strength (can't be diluted by distributed attacks) but also a weakness (small attackers are diluted by normal traffic).

### Gap E: Phase 2/3 IPs skip TEA entirely

**File:** `backend/transport/zmq_receiver.py:201-221`

IPs in Phase 2 (Time Ban) or Phase 3 (Blackhole) get `tea_attack_pattern=False` hardcoded. This is by design (keep scoring during ban for probation evidence). But it means:
- During a ban, TEA doesn't see those flows
- When the ban expires and the IP enters probation, TEA needs to re-detect the attack pattern from scratch
- If the attack resumes immediately after ban expiry, there is a detection gap

### Gap F: Initial learning phase blinds TEA

**File:** `backend/pipeline/entropy_analyzer.py:20`

```python
TEA_LEARN_INTERVALS = 30
```

During the first 30 intervals (30 seconds with 1s poll), TEA is building its baseline. `is_learned=False` means all z-scores are 0 and no attack detection occurs. An attack that starts within the first 30 seconds of the backend running will not be flagged by TEA.

## Verification Steps

To determine which gap(s) are causing attacks to get through in practice:

1. **Confirm A:** Check if `should_submit()` ever returns False. Add a counter. If it never returns False, TEA's output is irrelevant and the problem is upstream (TEA not detecting) or downstream (mitigation ignoring TEA).

2. **Confirm B:** During an attack that TEA misses, log `size_collapsed`, `intensity_collapsed`, `size_z`, `intensity_z`, and `attack_sigma`. Check if only one dimension collapsed, or if the z-scores didn't reach the sigma threshold.

3. **Confirm C:** Log `dynamic_attack_sigma()` values during normal traffic and during attacks. If sigma is consistently at the 3.5 cap, the threshold is too high for this network's traffic profile.

4. **Confirm D:** Count unique attacker IPs vs total unique IPs per TEA window. If attackers are < 10% of total IPs, their signal may be diluted in the aggregate variance.

5. **Confirm E:** Check if attacks resume immediately after ban expiry. Log TEA's `is_attack_pattern` in the first 5 seconds after a ban expires.

6. **Confirm F:** Check if attacks in the first 30 seconds of a backend run are missed by TEA.

## Fix Direction

> [!warning] Do not fix without verifying which gap(s) are actually causing misses.

### For Gap A (should_submit always True)
See [[bugs/tea-if-feedback-loop-missing]] for fix options.

### For Gap B (AND gate too strict)
Consider changing the gate to OR with differentiated confidence:
- Both collapsed -> `is_attack_pattern=True`, confidence="high"
- One collapsed -> `is_attack_pattern=True`, confidence="moderate" (currently this is not an attack pattern)
- Neither collapsed -> `is_attack_pattern=False`

Or: add a third dimension (e.g., `proto_entropy` collapse) to catch attacks that don't affect size/intensity variance.

### For Gap C (dynamic sigma too aggressive)
Cap the sigma lower (e.g., max 3.0 instead of 3.5), or use a fixed sigma. The dynamic scaling was designed to reduce false positives in variable traffic, but it may be overcorrecting.

### For Gap D (aggregate dilution)
Consider per-IP or per-subnet TEA profiles in addition to the global aggregate. The `_IpEntropyProfile` class exists (`entropy_analyzer.py:182-247`) but is never used in the detection path (only via `update_ip()` which has no callers).

### For Gap E (Phase 2/3 TEA skip)
Reduce the skip window, or add a "resume detection" trigger when ban expires so TEA can re-learn faster.

### For Gap F (initial learning phase)
Reduce `TEA_LEARN_INTERVALS` or use a faster initial learning path (e.g., seed baselines from the first 5 samples instead of waiting for 30).

## Fix Verified

- Date: 2026-08-23
- Changes: `TEA_LEARN_INTERVALS` reduced to 15; dynamic sigma capped lower; `proto_entropy` added as third dimension; AND gate relaxed to OR with differentiated confidence; `should_submit()` now gates low-confidence results; per-IP profiles wired in `zmq_receiver.py`.
- Verification: `scratch/verify_tea_fix.py` and `scratch/verify_consolidated_fixes.py` both pass.

### Final review fixes (2026-08-23)

- Removed change-tracking metadata comments from `entropy_analyzer.py`.
- Added `proto_entropy` and `proto_zscore` to the TEA result dict, `_neutral()`, and the expert event payload for observability.

## Remaining Issues After Task 2 Fix (added 2026-08-24)

Re-investigation of the current code found four issues still causing inconsistent TEA verdicts for attacker traffic.

### Issue 1: Per-IP verdict still uses AND (not relaxed to OR)

**File:** `backend/pipeline/entropy_analyzer.py:259`

The Task 2 fix relaxed the global gate from `size_collapsed AND intensity_collapsed` to OR. But the per-IP verdict in `_IpEntropyProfile.verdict()` still requires BOTH conditions:

```python
if rising and repetitive:    # line 259 - requires BOTH
    return "attack"
```

A fast-rising attack that hasn't accumulated enough samples for low entropy yet will not satisfy `repetitive`. The verdict falls through to "uncertain" (line 270) or even "normal" (line 263 if declining). This is the same AND-too-strict problem as the old global gate, just in a different code path.

**Fix direction:** Change to `rising OR repetitive` with differentiated confidence, matching the global gate pattern.

### Issue 2: Dead code in confidence assignment

**File:** `backend/pipeline/entropy_analyzer.py:414`

```python
if is_attack_pattern:                                    # line 407
    ...
elif size_collapsed or intensity_collapsed or proto_collapsed:  # line 414 - UNREACHABLE
    confidence = "moderate"
```

Line 414's condition is identical to `is_attack_pattern` (line 400: `size_collapsed or intensity_collapsed or proto_collapsed`). The `elif` can never be True because the `if` already caught it. This is a leftover from the AND-to-OR refactoring. Not a functional bug (the `else` at line 413 already handles single-collapse as "moderate"), but indicates the refactoring was incomplete.

### Issue 3: Frontend verdict display is binary (no "Uncertain" state)

**File:** `frontend/static/expert.js:725-731`

```javascript
if (tea && tea.global && tea.global.is_attack) {
    verdictEl.textContent = 'Anomaly';
} else {
    verdictEl.textContent = 'Normal';    // <-- shows Normal when TEA is learning or uncertain
}
```

The `ep-verdict` element only shows "Anomaly" or "Normal". During the learning phase, when TEA hasn't detected anything yet, or when detection is marginal, the verdict shows "Normal" (green). This is actively misleading. The status badge (`tea-switch-status`) does show "LEARNING", but the verdict text does not reflect uncertainty.

**Fix direction:** Add a third state for "Uncertain" or "Learning" in the verdict text, or at minimum show "Learning" when `!tea.is_learned`.

### Issue 4: 1-second result cache causes stale verdicts

**File:** `backend/pipeline/entropy_analyzer.py:305`

```python
if now - self._last_eval_time < self._eval_interval and self._global_state.last_result:
    return self._global_state.last_result
```

All flows within a 1-second window get the same TEA result. If the first flow in the window is from a legit host before attack flows arrive, all attacker flows in that second inherit `is_attack_pattern=False`. Combined with the per-IP override in `zmq_receiver.py:248-252`, this can partially compensate, but the per-IP verdict needs `IP_PROFILE_MIN_SAMPLES=5` samples before it produces anything other than "uncertain".

This is a design tradeoff (TEA runs once per poll cycle, not per flow), but it means detection latency is at least 1 second plus the per-IP warmup time.

## Related Notes

- [[backend/tea-analysis]]: TEA design and detection logic
- [[tasks/tea-desensitization-fix]]: the prior fix that addressed baseline drift
- [[bugs/tea-if-feedback-loop-missing]]: TEA's output has no effect on the pipeline
- [[backend/mitigation]]: state machine phases that skip TEA
- [[tasks/regression-fix-plan-2026-08-24]]: P5 fix addresses remaining per-IP AND gate, dead code, and sigma cap
