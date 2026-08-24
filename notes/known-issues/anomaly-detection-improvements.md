---
created: 2026-08-23
last-updated: 2026-08-23
status: draft
tags:
  - backend
  - pipeline
  - tea
  - prefilter
  - architecture
  - enhancement
---

# Anomaly Detection Architecture Improvements

> [!note] This is a design improvement note, not a bug report.
> The current anomaly detection design is sound (layered gates + ML), but has several gaps that reduce effectiveness. This note documents suggestions for improvement.

## Current Architecture

```
Traffic -> [Flood Prefilter] -> [TEA] -> IF -> RF -> Mitigation
              (burst gate)    (variance gate)  (per-flow ML)  (attack type)
```

### What Works Well

1. **Defense in depth**: Multiple layers (prefilter, TEA, IF, RF) provide redundancy
2. **TEA learns from IF**: Feedback loop via `feedback()` calibrates TEA's baselines
3. **Fast mitigation**: Prefilter provides immediate quarantine for obvious attacks
4. **Per-flow classification**: IF handles individual flow anomalies
5. **Attack labeling**: RF classifies attack type (SYN/ICMP/UDP) for mitigation tuning

### What's Broken

1. **TEA's gate is always open**: `should_submit()` always returns True, so TEA's analysis has no effect on the pipeline
2. **TEA only sees aggregate data**: Small attackers are diluted in switch-wide variance
3. **TEA's AND gate too strict**: Requires both size AND intensity variance to collapse
4. **TEA's dynamic sigma too high**: Cap at 3.5 makes detection harder in variable traffic
5. **TEA's learning phase too long**: 30s blind spot at startup
6. **Prefilter only detects bursts**: Misses low-rate, sustained attacks
7. **No feedback from TEA to IF**: TEA's global view doesn't help IF's per-flow analysis
8. **No feedback from IF to prefilter**: Prefilter doesn't learn which burst patterns are actually attacks

## Suggested Improvements

### 1. Make TEA a Functional Gate (High Priority)

**Problem:** TEA's `should_submit()` always returns True.

**Fix:** Return False when TEA is confident it's normal (flash crowd).

```python
def should_submit(self, tea_result, is_flood_prefilter_flagged):
    if is_flood_prefilter_flagged:
        return True  # Prefilter flagged, always submit
    if not tea_result.get("is_learned"):
        return True  # TEA not learned, let IF decide
    if tea_result.get("is_attack_pattern"):
        return True  # TEA detected attack, submit to IF
    if tea_result.get("confidence") == "moderate":
        return True  # TEA uncertain, let IF decide
    return False  # TEA confident it's normal (flash crowd), block gate
```

**Impact:** TEA can filter out obvious non-attacks, reducing false positives and IF load.

### 2. Add Per-IP TEA Profiles (Medium Priority)

**Problem:** TEA only sees aggregate switch data. Small attackers are diluted.

**Fix:** Use the existing `_IpEntropyProfile` class to track per-IP variance.

```python
# In zmq_receiver.py, after TEA runs on aggregate:
for src_ip in unique_ips:
    tea.update_ip(src_ip, pps, bps)
    ip_verdict = tea.get_ip_verdict(src_ip)
    if ip_verdict == "attack":
        # Flag this IP for IF
```

**Impact:** Detect small attackers that don't affect aggregate variance.

### 3. Add TEA Features to IF (Medium Priority)

**Problem:** IF doesn't benefit from TEA's global view.

**Fix:** Pass TEA's variance/z-scores as features to IF.

```python
# In worker.py, before IF inference:
if_vec = if_pipeline.extract_if_features(flow_stats)
# Add TEA features
if_vec.extend([
    flow_stats.get("tea_size_var", 0.0),
    flow_stats.get("tea_intensity_var", 0.0),
    flow_stats.get("tea_size_zscore", 0.0),
    flow_stats.get("tea_intensity_zscore", 0.0),
])
```

**Impact:** IF can use TEA's global context to improve per-flow classification.

> [!warning] Requires model retraining
> Adding features to IF requires retraining the model with the new feature set. The current `.pkl` artifacts won't work.

### 4. Add Feedback from IF to Prefilter (Low Priority)

**Problem:** Prefilter doesn't learn which burst patterns are actually attacks.

**Fix:** Track prefilter trip -> IF verdict correlation. Adjust thresholds based on false positive rate.

```python
# In flood_prefilter.py:
def on_packet(self, src_ip, proto):
    # ... existing logic ...
    if self._is_flagged(src_ip):
        # Track this trip
        self._trip_log.append((src_ip, time.time()))
        return True
    return False

# In worker.py, after IF verdict:
if flood_filter.is_flagged_any(src_ip):
    # Prefilter tripped, check IF verdict
    if not is_anomaly:
        # Prefilter false positive, adjust thresholds
        flood_filter.record_false_positive(src_ip)
```

**Impact:** Prefilter becomes more accurate over time.

### 5. Add Third Dimension to TEA (Medium Priority)

**Problem:** TEA only tracks size_var and intensity_var. Some attacks don't affect these.

**Fix:** Add proto_entropy collapse as a third dimension.

```python
# In entropy_analyzer.py, update() method:
proto_entropy = _shannon_entropy(list(protos.values()))
snapshot = {
    "size_var": size_var,
    "intensity_var": intensity_var,
    "proto_entropy": proto_entropy,  # Add this
    "unique_ips": len(unique_ips),
}

# In _GlobalEntropyState:
self.proto_base = _AdaptiveBaseline(TEA_LEARN_INTERVALS)

# In update(), attack detection:
proto_collapsed = proto_base.is_low(curr["proto_entropy"], attack_sigma)
is_attack_pattern = size_collapsed or intensity_collapsed or proto_collapsed
```

**Impact:** Detect attacks that don't affect size/intensity variance (e.g., ICMP floods with varied payload sizes).

### 6. Reduce TEA Learning Phase (High Priority)

**Problem:** 30s learning phase creates a blind spot at startup.

**Fix:** Reduce to 15s or use faster initial learning.

```python
TEA_LEARN_INTERVALS = 15  # Changed from 30
```

**Impact:** TEA can detect attacks sooner after backend restart.

### 7. Add Confidence-Based Routing (Medium Priority)

**Problem:** All flows go through the same pipeline regardless of TEA confidence.

**Fix:** Route flows based on TEA confidence.

```python
# In decision_engine.py:
if tea_result.get("confidence") == "high" and tea_result.get("is_attack_pattern"):
    # High confidence attack, fast-track to mitigation
    state_machine.on_detection(src_ip, if_score, attack_class, confidence)
elif tea_result.get("confidence") == "low":
    # Low confidence (flash crowd), skip mitigation
    log.debug("TEA confident it's normal, skipping mitigation")
else:
    # Moderate confidence, normal pipeline
    state_machine.on_detection(src_ip, if_score, attack_class, confidence)
```

**Impact:** Faster mitigation for high-confidence attacks, fewer false positives for low-confidence.

### 8. Add Ensemble Scoring (Low Priority)

**Problem:** TEA and IF scores are independent. No combined signal.

**Fix:** Combine TEA and IF scores into an ensemble score.

```python
# In decision_engine.py:
tea_attack = tea_result.get("is_attack_pattern", False)
tea_conf = tea_result.get("confidence", "low")

# Map TEA confidence to numeric score
tea_score_map = {"high": 0.9, "moderate": 0.6, "low": 0.3}
tea_score = tea_score_map.get(tea_conf, 0.5)

# Ensemble: weighted average
ensemble_score = 0.6 * if_score + 0.4 * tea_score

# Use ensemble_score for mitigation decisions
```

**Impact:** More robust detection by combining global (TEA) and per-flow (IF) signals.

### 9. Add Temporal Correlation (Low Priority)

**Problem:** Current detection is snapshot-based. Misses slow, sustained attacks.

**Fix:** Track attack patterns over time using a rolling window.

```python
# In decision_engine.py:
_attack_history = collections.deque(maxlen=60)  # Last 60 seconds

def on_result(...):
    # ... existing logic ...
    _attack_history.append({
        "ts": time.time(),
        "src_ip": src_ip,
        "if_score": if_score,
        "is_anomaly": is_anomaly,
    })
    
    # Check for sustained attack pattern
    recent = [x for x in _attack_history if time.time() - x["ts"] < 30]
    if len(recent) > 20 and sum(1 for x in recent if x["is_anomaly"]) > 15:
        # Sustained attack detected, escalate
        log.warning("Sustained attack pattern detected")
```

**Impact:** Detect slow, sustained attacks that don't trigger burst detection.

### 10. Add Anomaly Scoring to Prefilter (Low Priority)

**Problem:** Prefilter only detects bursts, not statistical anomalies.

**Fix:** Add statistical tests (e.g., z-score against baseline) to prefilter.

```python
# In flood_prefilter.py:
def _compute_anomaly_score(self, src_ip):
    # Compare current rate to baseline
    baseline_pps = self._get_baseline(src_ip)
    current_pps = self._get_current_rate(src_ip)
    if baseline_pps > 0:
        z_score = (current_pps - baseline_pps) / baseline_pps
        return z_score
    return 0.0

def is_flagged_any(self, src_ip):
    # Existing burst detection
    if self._is_burst_flagged(src_ip):
        return True
    # Add anomaly scoring
    if self._compute_anomaly_score(src_ip) > 3.0:
        return True
    return False
```

**Impact:** Prefilter can detect statistical anomalies, not just bursts.

## Implementation Priority

**High Priority (fix in current batch):**
1. Make TEA a functional gate (Task 3 in plan)
2. Reduce TEA learning phase (Task 3 in plan)

**Medium Priority (future work):**
3. Add per-IP TEA profiles
4. Add TEA features to IF (requires model retraining)
5. Add third dimension to TEA
6. Add confidence-based routing

**Low Priority (future work):**
7. Add feedback from IF to prefilter
8. Add ensemble scoring
9. Add temporal correlation
10. Add anomaly scoring to prefilter

## Bias Analysis and Research-Backed Improvements

> [!note] Research findings
> See [[known-issues/bias-reduction-research]] for detailed analysis with 25+ cited primary sources.

### TEA Biases

| Bias | Problem | Research-Backed Fix | Priority |
|------|---------|---------------------|----------|
| **Feature bias** | Uses only pkt_size_uniformity and flow_intensity | Add proto_entropy as 3rd dimension (Lakhina 2005), conditional entropy H(dst_port \| src_ip) (Bai 2026) | High |
| **Variance-only** | Only detects variance collapse | Add KL divergence from baseline (Gu 2005), monitor both directions (Berezinski 2015) | Medium |
| **Aggregate bias** | Small attackers diluted in switch-wide data | Activate per-IP entropy profiles, cross-domain confidence fusion (Zhang 2026) | High |
| **Protocol bias** | proto_entropy computed but unused | Use proto_entropy collapse as attack signal | High |
| **Temporal bias** | 1s windows miss short/slow attacks | Multi-scale windows (250ms + 1s + 5s) (Chen 2006), adaptive polling (3D-SNMP) | Medium |
| **Threshold bias** | Dynamic sigma scales with CV, harder in variable networks | EWMA-ARIMA hybrid (Bai 2026), threshold floor protection (Zhang 2026) | High |

### Flood Prefilter Biases

| Bias | Problem | Research-Backed Fix | Priority |
|------|---------|---------------------|----------|
| **Protocol bias** | Only monitors SYN/ICMP/UDP | Add TCP flag entropy, application-layer detection (Kemp 2023) | Medium |
| **Rate bias** | Only detects high-rate bursts | EWMA adaptive baseline with dual-alpha (Bai 2026), latency-based detection (Savchenko 2022) | High |
| **Per-IP bias** | Tracks per src_ip, misses distributed/spoofed | Destination-centric rate tracking, source IP entropy monitoring (Lakhina 2005) | Medium |
| **No learning** | Fixed thresholds, doesn't adapt | EWMA-ARIMA hybrid with feedback from ML stage (Bai 2026) | High |

### Key Research-Backed Techniques

1. **EWMA-ARIMA Hybrid Threshold (ATS-DTA, Bai 2026)**
   - Combines ARIMA for long-term trend forecasting with EWMA for short-term smoothing
   - Dynamic weight beta shifts based on prediction error
   - Feedback from ML stage adjusts thresholds (self-tuning)
   - **Applies to:** Both TEA and prefilter threshold bias

2. **Cross-Domain Confidence Fusion (Zhang 2026)**
   - Edge controllers track per-source confidence, aggregation controller fuses via consensus
   - FPR dropped from 8.87% to 1.96% in multi-controller SDN
   - **Applies to:** TEA aggregate bias

3. **Multi-Feature Joint Entropy (Mao 2018, Lakhina 2005)**
   - Joint entropy over multiple features (src_ip, dst_ip, dst_port, packet length)
   - Detects attacks invisible to any single feature
   - **Applies to:** TEA feature bias, protocol bias

4. **Bidirectional Entropy Monitoring (Berezinski 2015)**
   - Monitor entropy decrease (concentration/attack) AND increase (dispersion/scanning)
   - Multiple entropy types (Shannon, Renyi, Tsallis) for deception resilience
   - **Applies to:** TEA variance-only bias

5. **Multi-Scale Temporal Analysis (Chen 2006, 3D-SNMP)**
   - Spectral analysis at multiple time scales
   - Short bursts at fine scales, sustained patterns at coarse scales
   - **Applies to:** TEA temporal bias, prefilter rate bias

6. **Destination-Centric Rate Tracking (Lakhina 2005, MLDDoS 2025)**
   - Track aggregate rate to each dst_ip/dst_port
   - Flag when aggregate exceeds threshold even if no individual source exceeds per-IP threshold
   - **Applies to:** Prefilter per-IP bias

## Related Notes

- [[known-issues/bias-reduction-research]]: detailed research with 25+ cited primary sources
- [[bugs/tea-attacks-flagged-as-normal]]: current TEA gaps
- [[tasks/bug-fixes-batch-2026-08-23]]: current fix batch
- [[backend/tea-analysis]]: TEA design and detection logic
- [[backend/ml-pipeline]]: full pipeline data flow
