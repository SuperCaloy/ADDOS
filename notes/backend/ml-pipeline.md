---
created: 2026-08-19
last-updated: 2026-08-24
status: verified
tags:
  - backend
  - ml
  - pipeline
---

# ML Pipeline

Four cooperating modules under `backend/pipeline/`, plus the decision engine that consumes their output.

## Worker queue: `pipeline/worker.py`

- **Priority queue** (`PriorityQueue`, maxsize 1000) of tuples `(priority, seq, src_ip, flow_stats, switch_stats, enqueued_at, retry_count)`.
- `submit()`: priority 0 if `flood_filter.is_flagged_any(src_ip)` (flagged IPs jump the queue to fix live telemetry lag), else 1. Monotonic `seq` keeps FIFO within a priority.
- `_process_item()` core path:
  1. Skip if `ML_ENABLED=False`, invalid IP, or whitelist `{10.0.0.20, 10.0.0.21}` (duplicated whitelist).
  2. Skip zero-packet flows and *young* flows (`flow_dur < 0.05s` and `pkt_count < 1`) unless flood-flagged.
  3. **Low-rate gate**: skip flows below 0.05 pps; reported Normal without IF scoring.
  4. **Stale handling** (> `WORKER_ITEM_TIMEOUT_S` = 3s): flagged IPs get 1 priority requeue then a `timed_out=True` fallback callback (`state_machine.hold_ip()`); non-flagged silently dropped.
  5. **Inference cache** (`tracker.get_cached`): banned / high-confidence (`conf >= 0.70` and class != Uncertain) results locked + replayed; banned IPs recheck every 10s window.
  6. Run **IF** → **TEA feedback** (`feedback(is_anomaly)`: locks baselines on first anomaly, unlocks after `TEA_FEEDBACK_UNLOCK_STREAK = 10` consecutive normal results).
  7. **Flood prefilter override**: flagged IP + IF score ≥ threshold → forced anomaly.
  8. Run **RF** only if IF flagged anomaly (merges flow+switch stats, forces `ip_proto`); restores prior confident class if RF says "Uncertain" and prior conf ≥ 0.70.
  9. Log `[SCAN]` line; push `decision_engine.push_scan_result`; update/clear cache; fire result callback.
- `start()`: worker threads = `cpu_count - RYU_PINNED_THREADS(2) - 2` headroom. Idle queue triggers cache/flood-filter purge.

## Flow tracker: `pipeline/flow_tracker.py`

- `FlowEntry`: per-src_ip latest `flow_stats`, `pkt_count`, first/last seen (LRU `OrderedDict`, cap `FLOW_TRACKER_CAP = 500`).
- `InferenceCacheEntry`: cached `if_score/is_anomaly/attack_class/confidence` with 1s TTL (`INFERENCE_CACHE_TTL_S`).
- Singleton `tracker`. All methods lock-protected.

## Flood prefilter: `pipeline/flood_prefilter.py`

Fast, packet-level, sub-second detection ahead of the 1s stats poll.

- `_PROTO_CONFIG`: SYN `(100, 1.0s)`, ICMP `(50, 1.0s)`, UDP `(50, 1.0s)`.
- **Two trip mechanisms** (`on_packet`): full-window limit, or **burst sub-window** (40% of limit within 0.1s or 0.5s).
- `_check_correlation()`: 2+ protocols active simultaneously → multi-vector flag.
- `on_ack()`: SYN-ACK pops one half-open SYN entry, rate-limited to max 20 pops/s per src_ip (`_ACK_POP_MIN_INTERVAL = 0.05`). Prevents attackers from pairing SYNs with their own ACKs to keep half-open count near zero.
- Query/clear: `is_flagged`, `is_flagged_any`, `is_correlated`, `get_trigger_reason`, `clear_flag`, `purge_stale`.
- Singleton `flood_filter`, consumed by `zmq_receiver` and `worker`.

## TEA: `pipeline/entropy_analyzer.py`

**Temporal Entropy Analysis**: distinguishes **flash crowds** from **attacks** using global feature variance.

- `_shannon_entropy()`: classic Shannon entropy (still available for protocols/ports).
- `_AdaptiveBaseline`: per-dimension online baseline.
  - **Learning phase:** up to `TEA_LEARN_INTERVALS = 15` samples, early-stop when variance stabilizes (observed at window 10 on real traffic).
  - **Adaptive phase:** dynamic EMA alpha (0.02-0.10, inverse of coefficient of variation); **robust EMA** rejects samples beyond 3.0 dynamic-sigma. Learning-phase pushes ignore the lock until baselines declare learned (cold-start window).
  - **Latched feedback lock:** `feedback(True)` freezes baseline updates; `feedback(False)` unlocks after a 10-result normal streak. All four baselines (size, intensity, proto, share) latch together via `feedback`/`confirm_*`/`is_locked`.
- `_GlobalEntropyState`: aggregates all network telemetry into a rolling window; baselines: `size_base` (packet-size uniformity), `intensity_base` (flow intensity), `proto_base` (protocol entropy), `share_base` (uniform-share fraction).
- `_IpEntropyProfile`: per-IP pps/bps trend + entropy (min 5 samples, window 20); `verdict()` → `attack`/`normal`/`uncertain`; wired into `zmq_receiver` (`update_ip` / `get_ip_verdict`, attack verdict overrides the global result per flow). Measured on real capture: 43.3% attack-verdict share on known attackers, 0.0% on benign, with flapping across states.
- `update(0, flows)` → rate-normalized features (`log1p(avg_bytes_per_pkt)`, `log1p(pps*bps)`); global gate is an OR over seven channels: size/intensity collapse AND surge (dynamic sigma), proto collapse and proto surge (static sigma), plus mechanized_cluster (uniform-share high side). Baselines learn only on non-flagged windows. Real-data evidence and residual limitations in [[tasks/tea-verdict-fix-plan-2026-08-24]].
- `should_submit(...)`: **advisory** - always returns True; counts `would_block_count` when it would have vetoed (learned + quiet + unflagged). Expert payload exposes it as `_would_block_count`.

## Decision engine: `pipeline/decision_engine.py`

The hub: consumes worker results, orchestrates mitigation and metrics.

- **ML OFF path:** counts normal, writes traffic_summary, no mitigation.
- **Timeout path:** `state_machine.hold_ip(src_ip, reason="queue_timeout", ttl_s=15.0)` + `malicious_dropped`.
- Writes `writer.log_detection_features(...)` (full feature snapshot).
- **Normal result** → ground-truth traffic summary (TN/FN).
- **Anomaly path:**
  - Known legit host (`_LEGIT_HOST_IPS` = 10.0.0.1-5) → counts FP immediately.
  - **Confidence lock** (`_conf_lock`): highest-seen confidence + class per IP.
  - `predicted_class` = "DDoS" if class known else "Anomaly"; priority via `_assign_priority()` (High if `if_score >= threshold*1.2` AND `conf >= 0.75`).
  - Always refreshes quarantined IPs via `state_machine.update_observation()`.
  - **TEA confidence-based routing**: after `_tea_result` is built, a high-confidence attack pattern (`tea_attack_pattern=True` and `tea_confidence="high"`) bumps a Low priority up to High so the worker fast-tracks the flow.
  - **TEA mitigation gate**: flash crowds logged but NOT mitigated.
  - If mitigating: `resource_guard.set_attack_proto()`, `recent_pps`, checks DB `ip_attack_history` → `on_reoffence()` (escalated ban) vs `on_detection()` (fresh), measures `mitigation_ms`.
  - Writes `writer.log_mitigation_event(...)` with latency fields.
  - Computes IF + RF ground-truth (TP/FP/TN/FN, per-class confusion matrix) → `writer.log_traffic_summary()`.
  - **SSE events** with 5s dedup, force-pushed on phase upgrades.
- Rolling buffers: `_scan_buffer` (200), `_debug_buffer` (200), `_sse_buffer` (200).
- `get_stats()`: `total_packets` = malicious + normal (excludes raw OVS counts); `active_threats`; `fp_rate`; `avg_latency_ms`.
- `record_false_positive()` / `record_dropped_packets()`.

## Related notes

- [[backend/models]]: the IF/RF inference used in step 6-8.
- [[backend/mitigation]]: what happens after a detection.
- [[overview/architecture]]: wiring and end-to-end flow.