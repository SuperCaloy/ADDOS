---
created: 2026-08-23
last-updated: 2026-08-23
status: planned
area: [frontend, backend]
---

# Expert Mode Visualization Plan (TEA + Full Review)

## Part A: TEA Feedback-Loop Visualization

### Current state
- IF to TEA feedback is a static dashed arrow on the canvas (`expert.js:293`, rendered `:379-407`) labeled "learns baseline". Particles only run on forward paths (`expert.js:349-350`).
- TEA card (`expert.js:697-771`) shows only a status badge plus two z-score bars (size, intensity). No baseline, sigma, confidence, or learning state.
- Real-time SSE `tea_update` is discarded: `updateTEASwitch()` is a no-op (`expert.js:787-791`). All TEA UI is 2s-poll driven.
- The feedback mechanism itself is a lock/unlock latch, not a numeric adjustment (`entropy_analyzer.py:452-465`): IF anomaly locks baselines (freeze learning); 10 consecutive normals unlock.
- `size_baseline` / `intensity_baseline` are returned by `expert.py:109-110` but never rendered.

### Suggested changes (TEA)
1. Animate the feedback edge: distinct particle along IF to TEA per `inference` event, colored red (lock) / green (unlock).
2. Show latch state near the arrow: "learning frozen" / "learning active" plus streak count (e.g. 7/10).
3. Add baseline marker and sigma band on each z-score track so "current vs threshold" is legible.
4. Add learning-progress indicator (12/15 intervals) during LEARNING.
5. Show sigma threshold plus confidence chip (HIGH/MODERATE/LOW) instead of raw z-score only.
6. Add a plain-English caption per element; add a legend for the z-score track.
7. Fix two mislabeled metrics: "IP entropy" actually shows `size_var` (`expert.js:560-561`); "Model verdict / IF+RF combined" actually shows TEA's verdict (`expert.js:524,563-569`).

### Backend prerequisites (TEA)
- Expose in `expert.py` tea_global: `_locked`, `_fb_normal_streak`, `dynamic_attack_sigma()`, `alpha`, `confidence` (all already computed in `entropy_analyzer.py`, just not serialized).

### Decision (TEA, resolved 2026-08-23)
- Do both: keep the lock/unlock latch (arrow + streak count) as the primary real-time indicator, and add the baseline-drift time-series on top (baseline mean/sigma trend line for size and intensity).

---

## Part B: Full Expert Mode Review — Additional Suggestions

### B1. Correctness bugs (mislead a reviewer, fix first)

| # | Bug | Where | Effect |
|---|---|---|---|
| 1 | Resource Guard tier is always "OK" | `resource_guard._classify()` returns level as a local, never stores `_tier`; `expert.py:154-156` reads a nonexistent `_tier` | Badge can never show WARN/HIGH/CRIT |
| 2 | Blackhole "24h TTL" is wrong | `expert.js:823` hardcodes "24h"; actual `BLACKHOLE_TTL_SECONDS = 3600` (1h) | Misstates mitigation duration |
| 3 | `escalate_at_sec` hardcoded 30 | `expert.py:149`; actual `SINKHOLE_OBSERVE_SECONDS = 30` and max 90 | Progress bar denominator may be wrong |
| 4 | `cache_hit_rate` always 0.0 | `flow_tracker` never defines `_cache_hits` / `_cache_lookups`; `expert.py:58-60` uses getattr default | Dead metric shown as real |
| 5 | Hardcoded thresholds drift risk | IF threshold + RF conf gate duplicated in `expert.py:167,172` and `expert.js:645,198` instead of `loader.if_threshold` / `rf_conf_gate` | Silent drift if model contract changes |
| 6 | "IP entropy" / "Model verdict" mislabels | `expert.js:523,560-561,524,563-569` | See Part A item 7 |

### B2. Invisible pipeline stages and decisions (backend has them, UI does not)

- Deception / Sinkhole module has no pipeline node; only a terminal list (`expert.js:853-868`). The escalate-vs-release decision (`deception.py:211-265`) and cumulative-time ceiling are invisible.
- Resource Guard has no node; only the (broken) tier badge. CPU/mem throttle, `throttle_delay`, and `proto_block` rule install/remove are unrepresented.
- State-machine phase transitions: 4 phase boxes show counts, but no transition flow, no reason, no escalation path. Biggest gap: transition `reason` strings ("Attack Stopped", "Blackhole TTL Expired", "high priority detection", "prefilter trip", etc.) are logged but never stored on `IpState` or surfaced to the frontend.
- Flood prefilter activity: trips emit no expert SSE event (log lines only). Only aggregate `flood_prefilter_flagged` count is shown, with no per-protocol (SYN/ICMP/UDP) breakdown, no burst-vs-limit distinction, no correlation (multi-vector) flag.
- TEA mitigation gate (`decision_engine.py:353-419`): flash-crowd "log only" vs submit routing is invisible.
- Re-offence / reputation routing (`on_reoffence`, prior-ban DB lookup) not shown.
- Hold / unscored path (`hold_ip`, queue-timeout fallback) invisible.
- Priority assignment + confidence lock not shown.
- Enforcement command types: the decision node just says "drop-rule", but backend emits distinct commands (rate_limit, block, clear, redirect, proto_block).

### B3. Data computed but not surfaced

- IF 16-feature and RF 15-feature vectors never emitted to any live panel.
- Prefilter window/burst counts, `_correlated` set, trigger-reason strings (`get_trigger_reason` is dead code) not surfaced.
- TEA fields dropped by `expert.py`: `proto_entropy`, `proto_zscore`, `size_delta`, `intensity_delta`, third (protocol) channel entirely.
- Worker queue drops / timeout retries: log-only, no UI.
- decision_engine `_stats`, hold stats, deception `_cumulative_time`: not in expert API.

### B4. Real-time / lag

- SSE covers only TEA (`entropy_analyzer.py:407-422`) and IF/RF (`worker.py:267-276`); nothing for prefilter or mitigation transitions (those go through a separate `/api/events` stream consumed by `log.js`).
- Main ML panel is 2s-poll only; `updateIFBar` is also a no-op (`expert.js:793-795`).
- All scan/debug buffers are `deque(maxlen=200)` ring buffers that silently drop events under load; `expert.py` reads only `[:50]`.

### B5. Dead / duplicate code (ip-drawer.js)

Decision: wire up the per-IP expert trace rather than removing it, since the underlying per-IP TEA data is real (`entropy_analyzer.update_ip` is called at `zmq_receiver.py:180`). Do the data-shape fixes first, then enable the feature.

- `window.EXPERT_MODE` is hardcoded `false` (`dashboard.html:340`) and never flipped by `toggleExpertMode()`. Consequently the entire per-IP algorithm trace in `ip-drawer.js:878-1048` (TEA per-IP profile, 16/15 feature vectors, decision trace) is dead code, duplicating `expert.js` functionality.
- Correction to prior note: `entropy_analyzer.update_ip` does have a caller (`zmq_receiver.py:180`), so per-IP TEA verdicts are real, not "always uncertain".

Wire-up sub-task (order below):
1. Fix data-shape mismatches before enabling:
   - `confidence`: unify to a numeric value across `/api/ip_detail`, `/api/ip_detail/<ip>/live`, and `/api/quarantine_list` (currently a formatted string like "92.3%" in `state_machine.to_api_dict` vs numeric elsewhere).
   - `phase`: unify to a consistent type (currently int in `ip_detail.py:51` vs label string in `quarantine_list`); the drawer expects numeric `st.phase` (`ip-drawer.js:1021`).
   - `st.last_seen`: never emitted by either backend payload; add it.
   - live `first_seen` is `None`; populate it.
   - `tea_ip_profile` only in the live payload, missing from DB fallback; guard is already present but historical IPs show nothing.
   - expert-trace feature fields (`flow_count_per_src`, `tp_src`, `tp_dst`, `ip_proto`, `pkt_byte_rate_ratio`, `flow_intensity`, `bytes_per_duration`, `flow_src_intensity`) not in the live payload, so they default to 0; add them.
2. After the shape fixes, wire the toggle: set `window.EXPERT_MODE = true` from `toggleExpertMode()` so the drawer trace is reachable.
3. Fix stale polling comments in `stats.js` (says 30s/5s; actually 1s from `dashboard.html:354-355`).

### B6. Clarity for a thesis audience (cross-cutting)

- Add a single consistent legend explaining color semantics (green=normal, red=attack, amber=warning) used across pipeline, ML panel, and mitigation panel.
- Add per-panel plain-English captions: what the panel proves about the pipeline.
- Distinguish enforcement command types in the diagram instead of one generic "drop-rule".
- Surface transition reasons in the mitigation terminal so phase changes are self-explanatory.
- Unify the two "Expert" implementations (expert.js vs ip-drawer trace): wire `window.EXPERT_MODE` (per B5) and dedupe shared rendering so the two do not diverge.

### B7. Scope removals (decided 2026-08-23)

Remove two low-value sections from Expert Mode:

- TEA Per-IP Verdicts: the `tea-ip-pill` list rendered in `renderMLPanel` (`expert.js:773-783`, from `teaData.per_ip_verdicts`; backend `expert.py:117-121`). Redundant with the per-IP detail shown in the wired-up drawer trace (B5); the ML panel should focus on the global aggregation only.
- Active Sinkholes: the terminal-feed list rendered in `renderMitigationPanel` (`expert.js:852-868`; backend `expert.py:141-151`). Redundant with the mitigation state terminal and out of scope for the thesis narrative.

When removing, also drop the now-unused backend fields if nothing else reads them (verify against B5 drawer wiring before deleting the API keys).

---

## Suggested implementation order
1. Fix correctness bugs (B1) — cheap, high impact on credibility.
2. TEA loop + card improvements (Part A): latch arrow + streak, baseline marker + sigma band, learning progress, confidence chip, captions/legend, and the baseline-drift time-series for size + intensity.
3. Backend API additions (expose transition reasons, prefilter breakdown, TEA channel 3, lock/streak/confidence).
4. New visual elements: deception + resource-guard nodes, prefilter per-protocol activity, phase-transition flow with reasons, command-type distinction.
5. Wire up ip-drawer.js expert trace (B5): fix data-shape mismatches first (confidence type, phase type, missing fields), then flip `window.EXPERT_MODE` on.
6. Legends/captions pass for thesis readability.

## Verification
- No backend test infra; use `scratch/` scripts for API-shape checks and Playwright e2e (`test/e2e/`) for rendering/update behavior. Confirm `/api/expert/live` returns the new fields and the panel renders them without console errors.

## Related notes
- [[tasks/tea-desensitization-fix]]: the feedback latch semantics.
- [[frontend/expert-pipeline-visualization]]: pipeline canvas architecture.
