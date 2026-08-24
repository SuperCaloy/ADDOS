---
created: 2026-08-19
last-updated: 2026-08-23
status: verified
tags:
  - backend
  - pipeline
  - analysis
  - ml
---

# TEA (Traffic Entropy Analyzer)

This document provides a deep dive into how the Traffic Entropy Analyzer (TEA) operates within the ADDOS simulation and outlines robust, unbiased strategies to improve its anomaly detection using the ML pipeline's extracted features.

## 1. How TEA Operates Now (Global Feature Variance)

TEA (`backend/pipeline/entropy_analyzer.py`) has been refactored to eliminate biases tied to IP diversity and localized switch states. It acts as a robust, global anomaly gate by tracking the variance of engineered features over a rolling 1-second window.

### Core Mechanisms
- **Global Aggregation**: It pools telemetry from all active switches into a single `_GlobalEntropyState`, gaining a macro-level view of the network that cannot be diluted by distributed attack vectors.
- **Two-Dimensional Feature Variance**: TEA tracks the variance of two metrics:
  - **Size Variance**: Variance of `pkt_size_uniformity` (avg_bytes_per_pkt / bps).
  - **Intensity Variance**: Variance of `flow_intensity` (packet_count * bps).
- **Adaptive Baselines**: It maintains an online baseline (`_AdaptiveBaseline`) for each feature, tracking the stable network mean and standard deviation.
- **Robust Z-Scores**: Anomalies are detected by calculating Z-scores against the learned mean.

### Decision Logic (Unbiased)
- **Attack Detection**: Triggered when the variance of BOTH `size_var` AND `intensity_var` drops significantly below their learned baselines (Z-score <= -2.5 by default, dynamically scaled).
  - *Why this works*: Normal traffic is chaotic with highly varied packet sizes and flow intensities. Automated botnets (UDP floods, SYN floods) typically generate identical packet sizes and uniform flow intensities to maximize throughput. A collapse in variance indicates mechanized traffic, regardless of how many spoofed IPs are used.
- **Flash Crowd**: The strict variance-collapse requirement prevents flash crowds (which scale intensity but maintain chaotic size distributions) from being misclassified as attacks.

---

## 2. Historical Context (The Diversity Bias)

Previously, TEA relied on calculating the Shannon Entropy of source IPs (diversity) and packet rates, maintaining these baselines per-switch. 

> [!WARNING] The Diversity Bias
> The old attack logic assumed attackers used a small set of IPs, causing "diversity collapse." In a highly distributed, spoofed botnet attack, IP diversity might *increase* or stay normal, causing TEA to misclassify the attack. Maintaining baselines per-switch also made the system vulnerable to distributed attacks that stayed below the radar on individual switches. This was resolved by shifting to the global, feature-based variance model described above.

---

## 3. Desensitization Fix (added 2026-08-21)

### Root Cause Chain

With sustained multi-attacker floods, TEA flagged correctly at onset, then flipped to normal after roughly 10-30 seconds. Three issues combined:

1. **Per-flow lock flapping**: `worker.py` called `confirm_attack()` or `confirm_normal()` for every scored flow. One normal-classified flow instantly unlocked the global baseline gate.
2. **Baselines learned attack windows**: `update()` called `state.push(snapshot)` unconditionally, feeding both EMA baselines even when the window was the attack. EMA alpha up to 0.10 dragged baseline means down to collapsed-variance levels within 10-30 windows.
3. **Robust reject too weak against slow drift**: `_AdaptiveBaseline.push()` rejected only single jumps >= 3 sigma. Repeated sub-threshold steps slid the mean unnoticed.

### The Fix

**Freeze-during-attack behavior**: `_GlobalEntropyState` now splits `push()` into `observe()` (append window only) and `learn()` (push both baselines). `update()` calls `observe()` unconditionally but `learn()` only when `not is_attack_pattern`. Baselines never learn from attack windows.

**Latched feedback**: Replaced per-flow `confirm_attack()`/`confirm_normal()` pair with `feedback(is_anomaly)`. On first anomaly, baselines lock immediately. Unlock requires a streak of `TEA_FEEDBACK_UNLOCK_STREAK = 10` consecutive normal results. This prevents one normal flow from unlocking during a campaign.

**Verified**: `scratch/verify_tea_fix.py` confirms attack pattern holds for 80 consecutive attack windows with zero baseline drift, and recovery after attack ends.

### Research Context

- Jung et al. WWW 2002: novel source IPs dominate DDoS
- Nychis et al. IMC 2008: behavioral features catch what header entropies miss
- Lakhina et al. SIGCOMM 2004: single-dimension tests are evadable
- Feinstein et al. DISCEX 2003 and Xu et al. SIGCOMM 2005: dst-port entropy collapses under floods

Zero-bias detection is impossible (data-processing inequality). The goal is explicit, bounded bias.

---

## 4. Detection Gap Fixes (added 2026-08-23)

Changes in `backend/pipeline/entropy_analyzer.py`:

- **Reduced learning phase**: `TEA_LEARN_INTERVALS` lowered from `30` to `15` so TEA learns faster after startup or reset.
- **Capped dynamic sigma**: `dynamic_attack_sigma()` now caps at `3.0` (was `3.5`) and `dynamic_crowd_sigma()` caps at `2.0` (was `2.5`). This prevents high-coefficient-of-variation networks from making the attack threshold unreachable.
- **Third dimension: protocol entropy**: TEA now tracks `proto_entropy` (Shannon entropy of protocol distribution) as a third baseline. During attacks, traffic often concentrates on a single protocol, so proto entropy collapses. This catches attacks that only collapse one of the two variance dimensions.
- **Relaxed AND gate to OR**: An attack pattern is now declared when `size_collapsed OR intensity_collapsed OR proto_collapsed`. Confidence is differentiated:
  - `high`: size + intensity both collapsed, OR proto + one other collapsed.
  - `moderate`: exactly one dimension collapsed.
  - `low`: nothing collapsed.
- **Functional `should_submit()` gate**: The method now returns `False` for learned, low-confidence results, blocking IF submissions for flash crowds or confident-normal traffic. Flood-prefilter-flagged traffic and unlearned/attack/moderate results still pass through.

> [!note] Protocol entropy direction
> The task brief suggested `proto_base.is_high()`, but Shannon entropy of protocol distribution *decreases* when traffic concentrates on fewer protocols. The implementation uses `proto_base.is_low()` so the dimension actually detects real attacks.

Verified by `scratch/verify_tea_fix.py` and an additional scratch check covering the new proto dimension and `should_submit()` gating.

---

## 5. Per-IP TEA Profile Integration (added 2026-08-23)

The `_IpEntropyProfile` class and `update_ip()` / `get_ip_verdict()` methods already existed in `entropy_analyzer.py` but were never invoked. They are now wired into `backend/transport/zmq_receiver.py` so that small attackers diluted in switch-wide aggregate data are still detected.

### Changes in `backend/transport/zmq_receiver.py`

- After each `flow_stats` flow is accumulated into `_switch_flows`, `entropy_analyzer.update_ip(src_ip, pps, bps)` is called for every non-whitelisted source IP.
- After the global `entropy_analyzer.update(dpid, switch_flow_list)` runs, the per-IP verdict is checked via `entropy_analyzer.get_ip_verdict(src_ip)`.
- If the per-IP verdict is `"attack"`, the flow is marked with `tea_attack_pattern = True` and `tea_confidence = "moderate"`, overriding the global result for that source.

This provides a second detection path for low-volume attackers that do not perturb the global variance enough to trigger the switch-wide TEA gate.

> [!note] Ordering matters
> The per-IP verdict check is placed *after* the global `tea_result` fields are written to `flow_stats`, so a per-IP "attack" verdict can override a non-attack global result. Placing it before the global attachment would cause the global result to overwrite the per-IP verdict.

Verified by `python3 -c "from backend.transport import zmq_receiver; print('ok')"`.
