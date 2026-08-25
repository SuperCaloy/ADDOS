---
created: 2026-08-21
last-updated: 2026-08-21
status: done
area: [backend]
---
	
# TEA Desensitization Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. (Subagent-driven development is unavailable in this environment: the `task` tool with `general` subagent is denied by permissions.)

**Goal:** Stop TEA from classifying sustained multi-attacker floods as normal, and stop the flood prefilter from being defeated by SYN+ACK self-pairing.

**Architecture:** Two targeted fixes. (1) TEA baselines stop learning from attack windows and the worker feedback latch requires a streak of normal results before unlocking, so adaptive baselines can no longer drift onto the attack signature mid-campaign. (2) The prefilter rate-limits ACK-driven decrements per source. No new modules, no new dependencies.

**Tech Stack:** Python 3, stdlib only (`threading`, `time`, `collections`), numpy already in use.

**Spec:** This plan implements findings documented inline below ("Discovery") and in [[backend/tea-analysis]]. No separate spec doc exists.

## Global Constraints

- No emojis anywhere (code, comments, commits).
- No em-dashes anywhere.
- No new comments in code unless mirroring an adjacent existing comment style; keep additions minimal.
- Do NOT commit: the user has not asked for commits; leave changes staged-free in working tree.
- Match existing code style: 4-space indent, snake_case, module-level UPPER_SNAKE constants near the top of `entropy_analyzer.py`.
- Verification uses scratch scripts because this repo has no pytest infra (only Playwright e2e). Scratch scripts live in `scratch/` and are throwaway.
- Run all python commands from repo root `/home/killua/Documents/ADDOS-NEW` using `python3`.

## Discovery (why this fix exists)

Symptom: with many simultaneous attackers, TEA flags correctly at onset, then flips to normal after roughly 10-30 seconds of sustained flooding.

Root cause chain, verified in code:

1. **Per-flow lock flapping.** `backend/pipeline/worker.py:205-213` calls `_tea.confirm_attack()` or `_tea.confirm_normal()` for every scored flow based on IF's verdict for that one flow. One normal-classified flow instantly unlocks the global baseline gate.
2. **Baselines learn attack windows.** `backend/pipeline/entropy_analyzer.py` `update()` calls `state.push(snapshot)` unconditionally; `push()` feeds `size_var`/`intensity_var` into both EMA baselines even when the window IS the attack. Once unlocked during a campaign, EMA alpha up to 0.10 drags baseline means down to collapsed-variance levels within ~10-30 windows.
3. **Robust reject too weak against slow drift.** `_AdaptiveBaseline.push()` rejects only single jumps >= 3 sigma. Repeated sub-threshold steps slide the mean unnoticed.

Secondary finding: `FloodPreFilter.on_ack()` pops one SYN entry for ANY TCP ACK with that src_ip. An attacker pairing SYNs with its own ACKs keeps the half-open count near zero, defeating both limit and burst rules.

Research context supporting the design direction (documented for the thesis, not needed to implement): Jung et al. WWW 2002 (novel source IPs dominate DDoS), Nychis et al. IMC 2008 (behavioral features catch what header entropies miss), Lakhina et al. SIGCOMM 2004 (single-dimension tests are evadable), Feinstein et al. DISCEX 2003 and Xu et al. SIGCOMM 2005 (dst-port entropy collapses under floods). Zero-bias detection is impossible (data-processing inequality); the goal is explicit, bounded bias.

## File Structure

- Modify: `backend/pipeline/entropy_analyzer.py` — windowing split from learning; latched feedback API.
- Modify: `backend/pipeline/worker.py` — call the latch instead of confirm pair.
- Modify: `backend/pipeline/flood_prefilter.py` — rate-limited ACK pops.
- Create (throwaway): `scratch/verify_tea_fix.py` — verification harness.
- Update later (Task 5): `notes/backend/tea-analysis.md`, `notes/backend/ml-pipeline.md`, this file's status.

---

### Task 1: Split window observation from baseline learning in TEA

**Files:**
- Modify: `backend/pipeline/entropy_analyzer.py` (`_GlobalEntropyState`, lines ~146-169; `update()`, lines ~301-347)

**Interfaces:**
- Consumes: existing `_AdaptiveBaseline.push(value)` unchanged.
- Produces: `_GlobalEntropyState.observe(snapshot)` (append window only) and `_GlobalEntropyState.learn(snapshot)` (push both baselines), used by `update()` in this task and referenced by Task 2's tests.

- [x] **Step 1: Add observe/learn methods to _GlobalEntropyState**

Replace the current `push` method:

```python
    def push(self, snapshot: dict) -> None:
        self.window.append(snapshot)
        self.size_base.push(snapshot["size_var"])
        self.intensity_base.push(snapshot["intensity_var"])
```

with three methods:

```python
    def observe(self, snapshot: dict) -> None:
        self.window.append(snapshot)

    def learn(self, snapshot: dict) -> None:
        self.size_base.push(snapshot["size_var"])
        self.intensity_base.push(snapshot["intensity_var"])

    def push(self, snapshot: dict) -> None:
        self.observe(snapshot)
        self.learn(snapshot)
```

(`push` stays for API compatibility.)

- [x] **Step 2: Rewire update() so baselines never learn attack windows**

In `update()`, make these exact edits:

a) Replace:

```python
        with self._lock:
            state = self._global_state
            state.push(snapshot)
```

with:

```python
        with self._lock:
            state = self._global_state
            state.observe(snapshot)
```

b) In the same locked block, change the early not-ready return so it still learns:

```python
            if not state.is_ready():
                res = self._neutral(size_var, intensity_var, learned=False)
                state.last_result = res
                return res
```

becomes:

```python
            if not state.is_ready():
                state.learn(snapshot)
                res = self._neutral(size_var, intensity_var, learned=False)
                state.last_result = res
                return res
```

c) Change the not-yet-learned neutral return path:

```python
        if not is_learned:
            log.debug("TEA global learning phase")
            res = self._neutral(size_var, intensity_var, learned=False)
```

becomes:

```python
        if not is_learned:
            log.debug("TEA global learning phase")
            with self._lock:
                state.learn(snapshot)
            res = self._neutral(size_var, intensity_var, learned=False)
```

d) After the attack-pattern computation, add conditional learning. Replace:

```python
        is_attack_pattern = size_collapsed and intensity_collapsed
        is_flash_crowd    = False # Redefine or remove for feature-based
```

with:

```python
        is_attack_pattern = size_collapsed and intensity_collapsed
        is_flash_crowd    = False # Redefine or remove for feature-based

        if not is_attack_pattern:
            with self._lock:
                state.learn(snapshot)
```

- [x] **Step 3: Smoke check**

Run: `python3 -c "from backend.pipeline.entropy_analyzer import entropy_analyzer; print(entropy_analyzer.update.__name__)"`
Expected: prints `update` with no traceback.

### Task 2: Latched feedback in EntropyAnalyzer

**Files:**
- Modify: `backend/pipeline/entropy_analyzer.py` (constants block lines ~19-27; `EntropyAnalyzer.__init__` line ~245; new method after `confirm_attack`, line ~415)

**Interfaces:**
- Consumes: `_GlobalEntropyState.size_base.lock()/unlock()`, same for `intensity_base` (existing methods).
- Produces: `EntropyAnalyzer.feedback(is_anomaly: bool) -> None`. Task 3 consumes exactly this signature.

- [x] **Step 1: Add the unlock-streak constant**

In the constants block after `TEA_ROBUST_REJECT_SIGMA = 3.0` add:

```python
TEA_FEEDBACK_UNLOCK_STREAK = 10
```

- [x] **Step 2: Add latch state in __init__**

Inside `EntropyAnalyzer.__init__`, after `self._ip_profiles: dict[str, _IpEntropyProfile] = {}` add:

```python
        self._fb_normal_streak = 0
```

- [x] **Step 3: Implement feedback()**

After the existing `confirm_attack` method add:

```python
    def feedback(self, is_anomaly: bool) -> None:
        # Latched: lock on first anomaly, unlock only after a clean streak.
        with self._lock:
            if is_anomaly:
                self._fb_normal_streak = 0
                self._global_state.size_base.lock()
                self._global_state.intensity_base.lock()
                return
            self._fb_normal_streak += 1
            if self._fb_normal_streak >= TEA_FEEDBACK_UNLOCK_STREAK:
                self._fb_normal_streak = 0
                self._global_state.size_base.unlock()
                self._global_state.intensity_base.unlock()
```

Note: do NOT call `self.confirm_attack()` / `confirm_normal()` from inside; they re-acquire `self._lock` and would deadlock.

- [x] **Step 4: Smoke check**

Run: `python3 -c "
from backend.pipeline.entropy_analyzer import EntropyAnalyzer
e = EntropyAnalyzer()
e.feedback(True); e.feedback(False); e.feedback(False)
print('ok')"`
Expected: prints `ok`.

### Task 3: Worker calls the latch

**Files:**
- Modify: `backend/pipeline/worker.py:205-213`

**Interfaces:**
- Consumes: `entropy_analyzer.feedback(is_anomaly: bool) -> None` from Task 2.

- [x] **Step 1: Replace the confirm pair**

Replace:

```python
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
            if is_anomaly:
                _tea.confirm_attack()
            else:
                _tea.confirm_normal()
        except Exception:
            pass
```

with:

```python
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
            _tea.feedback(is_anomaly)
        except Exception:
            pass
```

- [x] **Step 2: Smoke check**

Run: `python3 -c "import backend.pipeline.worker; print('ok')"`
Expected: prints `ok`.

### Task 4: Rate-limit ACK pops in flood prefilter

**Files:**
- Modify: `backend/pipeline/flood_prefilter.py` (burst constants block lines ~20-25; `__init__` line ~52; `on_ack` line ~118; cleanup paths lines ~147-170)

**Interfaces:**
- Consumes: nothing new.
- Produces: unchanged public API; `on_ack` now ignores pops closer than 50 ms apart per src_ip.

- [x] **Step 1: Add constant**

After `_BURST_FRACTION  = 0.4` add:

```python
# Min spacing between ACK-driven SYN-count decrements per src_ip (anti pairing)
_ACK_POP_MIN_INTERVAL = 0.05
```

- [x] **Step 2: Track last pop time**

In `__init__`, after `self._correlated: set[str] = set()` add:

```python
        self._ack_pop_ts: dict[str, float] = {}
```

- [x] **Step 3: Rewrite on_ack**

Replace:

```python
    def on_ack(self, src_ip: str) -> None:
        # SYN-ACK received — remove one half-open SYN entry
        with self._lock:
            win = self._windows[src_ip].get("SYN")
            if win and win.times:
                win.times.pop(0)
```

with:

```python
    def on_ack(self, src_ip: str) -> None:
        # Handshake completed — remove one half-open SYN entry, max 20/s per IP
        now = time.monotonic()
        with self._lock:
            if now - self._ack_pop_ts.get(src_ip, 0.0) < _ACK_POP_MIN_INTERVAL:
                return
            win = self._windows[src_ip].get("SYN")
            if win and win.times:
                win.times.pop(0)
                self._ack_pop_ts[src_ip] = now
```

- [x] **Step 4: Clean up the timestamp map**

In `clear_flag`, after `self._windows.pop(src_ip, None)` add:

```python
            self._ack_pop_ts.pop(src_ip, None)
```

In `purge_stale`, inside the stale loop after `self._windows.pop(ip, None)` add:

```python
                self._ack_pop_ts.pop(ip, None)
```

- [x] **Step 5: Smoke check**

Run: `python3 -c "from backend.pipeline.flood_prefilter import flood_filter; print('ok')"`
Expected: prints `ok`.

### Task 5: Verification harness + notes updates

**Files:**
- Create: `scratch/verify_tea_fix.py`
- Modify: `notes/backend/tea-analysis.md`, `notes/backend/ml-pipeline.md`, this file (frontmatter status)

**Interfaces:**
- Consumes: all prior tasks.

- [x] **Step 1: Write the verification script**

Create `scratch/verify_tea_fix.py`. It must patch `_eval_interval = 0` because `update()` otherwise throttles evaluation to once per second, which would starve a fast-running script:

```python
"""Throwaway verification for the TEA desensitization fix. Not a committed test."""
from backend.pipeline import entropy_analyzer as m
from backend.pipeline.flood_prefilter import FloodPreFilter


def main():
    # --- Prefilter: pure SYN burst still trips ---
    pf = FloodPreFilter()
    assert any(pf.on_packet("10.0.0.55", "SYN") for _ in range(120)), \
        "pure SYN burst must still trip"

    # --- Prefilter: SYN+ACK self-pairing can no longer suppress trips ---
    pf2 = FloodPreFilter()
    for _ in range(200):
        pf2.on_packet("10.0.0.66", "SYN")
        pf2.on_ack("10.0.0.66")
        if pf2.is_flagged_any("10.0.0.66"):
            break
    assert pf2.is_flagged_any("10.0.0.66"), \
        "SYN+ACK pairing must no longer fully suppress trips"
    print("prefilter OK")

    # --- Feedback latch: lock on anomaly, unlock only after clean streak ---
    m.TEA_LEARN_INTERVALS = 12
    ez = m.EntropyAnalyzer()
    ez.feedback(True)
    assert ez._global_state.size_base._locked, "anomaly must lock baselines"
    for _ in range(m.TEA_FEEDBACK_UNLOCK_STREAK - 1):
        ez.feedback(False)
    assert ez._global_state.size_base._locked, "must stay locked below streak"
    ez.feedback(False)
    assert not ez._global_state.size_base._locked, "must unlock after streak"
    print("latch OK")

    # --- TEA sustained campaign: pattern holds and baselines never drift ---
    a = m.EntropyAnalyzer()
    a._eval_interval = 0

    def send(flows):
        a._flow_buffer.clear()
        a._flow_buffer.extend(flows)
        return a.update(0, [])

    def normal():
        return [{"src_ip": f"10.0.{i}.x", "packet_count": 40 + i * 7,
                 "byte_count": 3000 + i * 911,
                 "packet_count_per_second": 30 + i * 11,
                 "byte_count_per_second": 4000 + i * 1300,
                 "ip_proto": 6} for i in range(25)]

    def attack():
        return [{"src_ip": f"10.0.1.{i}", "packet_count": 900,
                 "byte_count": 54000,
                 "packet_count_per_second": 800,
                 "byte_count_per_second": 48000,
                 "ip_proto": 6} for i in range(60)]

    for _ in range(40):
        r = send(normal())
    assert r.get("is_learned"), "baseline must learn"
    base_mean_size = r["baseline_mean_size"]

    flags = sum(bool(send(attack()).get("is_attack_pattern")) for _ in range(80))
    assert flags == 80, f"attack pattern must hold for whole campaign, held {flags}/80"
    assert r["baseline_mean_size"] == base_mean_size, "baseline drifted during attack"

    for _ in range(15):
        recov = send(normal())
    assert not recov["is_attack_pattern"], "verdict must recover after attack ends"
    print("TEA desensitization fix VERIFIED")


if __name__ == "__main__":
    main()
```

- [x] **Step 2: Run it**

Run: `python3 scratch/verify_tea_fix.py`
Expected output, all three lines:

```
prefilter OK
latch OK
TEA desensitization fix VERIFIED
```

If `attack pattern must hold` fails with held < 80, Task 1 conditional learning was wired wrong. If `baseline drifted` fails, the freeze path is not reached. If the pairing assertion fails, Task 4 spacing constant is not applied.

- [x] **Step 3: Delete or finalize scratch script**

Either delete `scratch/verify_tea_fix.py` or leave it clearly marked throwaway; do not wire it into any test runner.

- [x] **Step 4: Update notes**

Append a dated section `## Desensitization fix (added 2026-08-21)` to `notes/backend/tea-analysis.md`: root cause chain, the freeze-during-attack behavior, latch constant value, and the research bullets. Append a short dated subsection under the flood prefilter part of `notes/backend/ml-pipeline.md`: ACK pop rate limit and why. Set this task file frontmatter to `status: done`, tick all checkboxes, and add wikilinks to the updated notes.

## Out of scope (future work, documented in notes only)

- Aggregate victim-side rate tier with novelty ratio for the prefilter.
- New TEA channels: diversity_fraction, dst_port_entropy, young_flow_ratio. If implemented later, each new channel must be wired into both the `is_attack_pattern` gate and the latch's lock/unlock pair, or that channel will keep learning through attacks while the others freeze.
- Mahalanobis / PCA-subspace joint scoring replacing the independent z-score AND rule.
- Median/MAD baselines replacing EMA.
- Restoring real gating semantics in `should_submit` (currently returns True on every branch).
- Dead code: `update_ip` has no callers, so `_IpEntropyProfile` verdicts are always "uncertain".

## Related Notes

- [[backend/tea-analysis]]: updated with desensitization fix details.
- [[backend/ml-pipeline]]: updated with ACK pop rate limit.
