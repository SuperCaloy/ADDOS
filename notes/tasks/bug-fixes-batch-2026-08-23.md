---
created: 2026-08-23
last-updated: 2026-08-23
status: planned
area:
  - backend
  - frontend
  - mitigation
  - pipeline
---

# Bug Fixes Batch 2026-08-23

Compilation of 3 bugs verified today. Each bug has a detailed investigation note linked below. All fixes implemented and verified via `scratch/verify_consolidated_fixes.py`.

> [!note] TEA-IF feedback direction is by design
> TEA learning from IF (IF -> TEA) is intentional. TEA uses IF's per-flow verdict to calibrate what counts as anomalous. This is not a bug.

## Bugs

### 1. Reputation/Behavioral Scoring Not Increasing

**Note:** [[bugs/reputation-scoring-stalled]]

**Summary:** Behavioral reputation scores stay flat during sustained or repeated attacks. Repeat offenders do not escalate to blackhole.

**Root causes:**
- `record_offense()` only fires on `_clear()`, not on ban escalation
- `should_blackhole()` uses raw count instead of decay score
- `on_reoffence()` depends on stale DB state

**Files:** `backend/mitigation/behavioral.py`, `backend/mitigation/state_machine.py`

### 2. TEA Still Flags Real Attacks as Normal

**Note:** [[bugs/tea-attacks-flagged-as-normal]]

**Summary:** The desensitization fix from 2026-08-21 is present and verified. However, 6 remaining gaps allow some attacks through.

**Remaining gaps:**
- Gap A: `should_submit()` always True (TEA's output has no effect on mitigation)
- Gap B: AND gate too strict (both size AND intensity must collapse)
- Gap C: Dynamic sigma scales up to 3.5
- Gap D: Aggregate dilution (small attackers lost in switch-wide data)
- Gap E: Phase 2/3 IPs skip TEA entirely
- Gap F: 30s initial learning phase blinds TEA

**Files:** `backend/pipeline/entropy_analyzer.py`, `backend/transport/zmq_receiver.py`

> [!note] TEA-IF feedback direction is by design
> TEA learning from IF (IF -> TEA) is intentional. TEA uses IF's per-flow verdict to calibrate what counts as anomalous. This is not a bug. See [[bugs/tea-if-feedback-loop-missing]] for clarification.

### 3. Audit Log Updates Old Entry on Re-Attack

**Note:** [[bugs/audit-log-re-attack-update]]

**Summary:** Frontend collapses re-attack into old row because `_logRows` Map is keyed by IP only. Backend DB is correct.

**Root cause:** `_logRows` Map in `log.js` keyed by `src_ip` only; when released attacker re-attacks with same action, it updates old row instead of inserting new one.

**Files:** `frontend/static/log.js`, `backend/pipeline/decision_engine.py` (SSE payload)

## Implementation Plan

See `docs/superpowers/plans/2026-08-23-consolidated-bug-fixes-and-improvements.md` for the consolidated step-by-step implementation plan (supersedes `2026-08-23-bug-fixes-batch.md`).

## Architecture Improvements (Future Work)

> [!note] The current anomaly detection design is sound (layered gates + ML), but has gaps that reduce effectiveness.

See [[known-issues/anomaly-detection-improvements]] for detailed suggestions.

**High Priority (fix in current batch):**
- Make TEA a functional gate (already in Task 3)
- Reduce TEA learning phase (already in Task 3)

**Medium Priority (future work):**
- Add per-IP TEA profiles (detect small attackers diluted in aggregate)
- Add TEA features to IF (requires model retraining)
- Add third dimension to TEA (proto_entropy collapse)
- ~~Add confidence-based routing (fast-track high-confidence attacks)~~ implemented 2026-08-23 as Task 5; see `backend/pipeline/decision_engine.py`

**Low Priority (future work):**
- Add feedback from IF to prefilter (prefilter learns from false positives)
- Add ensemble scoring (combine TEA + IF scores)
- Add temporal correlation (detect slow, sustained attacks)
- Add anomaly scoring to prefilter (statistical tests, not just bursts)

## Bias Analysis

> [!warning] Both TEA and Flood Prefilter have significant biases

See [[known-issues/bias-reduction-research]] for detailed analysis with 25+ cited primary sources.

**TEA Biases:**
- Feature bias: Only uses pkt_size_uniformity and flow_intensity
- Variance-only: Only detects variance collapse, misses gradual attacks
- Aggregate bias: Small attackers diluted in switch-wide data
- Protocol bias: proto_entropy computed but unused
- Temporal bias: 1s windows miss short/slow attacks
- Threshold bias: Dynamic sigma scales with CV, harder in variable networks

**Prefilter Biases:**
- Protocol bias: Only monitors SYN/ICMP/UDP
- Rate bias: Only detects high-rate bursts
- Per-IP bias: Misses distributed/spoofed attacks
- No learning: Fixed thresholds, doesn't adapt

**Research-Backed Fixes:**
- EWMA-ARIMA hybrid threshold (Bai 2026)
- Cross-domain confidence fusion (Zhang 2026)
- Multi-feature joint entropy (Mao 2018, Lakhina 2005)
- Bidirectional entropy monitoring (Berezinski 2015)
- Multi-scale temporal analysis (Chen 2006)
- Destination-centric rate tracking (Lakhina 2005)

## Related Notes

- [[tasks/tea-desensitization-fix]]: prior TEA fix (2026-08-21)
- [[backend/mitigation]]: state machine and behavioral reputation
- [[backend/tea-analysis]]: TEA design and detection logic
- [[decisions/mitigation-event-logging-strategy]]: mitigation event ledger design
- [[known-issues/anomaly-detection-improvements]]: architecture improvement suggestions
- [[known-issues/bias-reduction-research]]: bias analysis with 25+ cited primary sources
