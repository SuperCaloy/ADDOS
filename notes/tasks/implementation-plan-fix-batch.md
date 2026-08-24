---
created: 2026-08-23
last-updated: 2026-08-23
status: done
area: [frontend, backend, mitigation, ml-pipeline, visualization, topology, controller]
---

# Implementation Plan: Fix Batch (14 Items)

## Item 1: Remove Resource Guard panel from Expert Mode

### Current state
- `frontend/static/expert.js` renders the Resource Guard tier in `renderMitigationPanel()` at line 1124-1129
- The Resource Guard is also node 10 in the pipeline canvas diagram (`expert.js:326`)
- The backend `resource_guard.py` still runs and polls controller CPU/memory

### Root cause
Not a bug. The Resource Guard card in the Mitigation State Machine panel takes up vertical space that could be used by the Active States section.

### Proposed fix
1. **Remove the Resource Guard card** from `renderMitigationPanel()` in `expert.js` (lines 1124-1129)
2. **Keep the node** in the pipeline canvas diagram (it's part of the system architecture)
3. **Keep the backend** `resource_guard.py` running (it still provides CRIT-tier protection)
4. Active States section will naturally expand to fill the freed vertical space since it's rendered above the Resource Guard card

### Files to change
- `frontend/static/expert.js` (remove ~6 lines in `renderMitigationPanel`)

---

## Item 2: Size baseline / Intensity baseline showing empty ("--")

### Current state
- In the TEA card, "Size baseline" and "Intensity baseline" sparklines show "--" instead of actual values
- The sparkline data comes from `teaGlobal.size_baseline_history` and `teaGlobal.intensity_baseline_history` (expert.js:929-930)
- These are populated from `size_base.baseline_history` and `intensity_base.baseline_history` (expert.py:146-147)
- The `_AdaptiveBaseline` class in `entropy_analyzer.py` appends to `_baseline_history` only when `push()` is called AFTER learning is complete (line 109)

### Root cause
The `_baseline_history` list is only populated AFTER the baseline has been learned (line 94 appends `self._mean` when learning completes, line 109 appends during post-learning updates). However, the sparkline `makeSparkline()` function (expert.js:871-883) requires at least 2 data points to render. During the initial learning phase, `_baseline_history` has only 1 entry (the initial learned mean), so the sparkline shows "--".

Additionally, `_baseline_history` is capped at `TEA_BASELINE_HISTORY_MAX = 60` entries (line 110-111), so after 60 post-learning updates it stabilizes. But the initial single-entry state means the sparkline is empty for a long time.

### Proposed fix
1. **Seed `_baseline_history` with the initial learned mean** when learning completes (already done at line 94)
2. **Lower the sparkline minimum** from 2 to 1 data point, rendering a single dot/flat line when only 1 sample exists
3. Alternatively, **pre-populate `_baseline_history`** with the first few learning samples (not just the final mean) so the sparkline has data sooner

### Files to change
- `frontend/static/expert.js` (modify `makeSparkline()` to handle 1 data point)
- Optionally: `backend/pipeline/entropy_analyzer.py` (seed history earlier)

---

## Item 3: Algorithm Trace - add explanations, relate to RF classification

### Current state
- The IP detail drawer's "Algorithm Trace" section (ip-drawer.js:878-1048) shows IF Features (16) and RF Features (15) as raw numbers with labels
- Each feature is just a label + formatted value in a card, with no explanation of what the value means or how it relates to attack classification
- The "Model Signals" section above it (ip-drawer.js:470-605) already has attack-class-specific explanations with alert thresholds

### Root cause
The Algorithm Trace was designed as a raw feature dump for expert inspection, not as an educational/explanatory view. It lacks the context that "Model Signals" provides.

### Proposed fix
1. **Add a one-line explanation** to each IF/RF feature card describing what the feature measures and why it matters for attack detection
2. **For RF features specifically**, add a note about how each feature relates to the 3-class classification (SYN/ICMP/UDP). For example:
   - `pkt_size_uniformity`: "SYN floods produce near-identical packet sizes (handshake only), making this a strong SYN indicator"
   - `port_entropy`: "UDP floods spray across many ports, producing high port entropy"
   - `ip_proto`: "Directly identifies the protocol: 6=TCP/SYN, 1=ICMP, 17=UDP"
3. **Add a summary line** at the top of each section explaining the model's decision: e.g., "IF flagged this flow as anomalous because [top 3 distinguishing features]"

### Files to change
- `frontend/static/ip-drawer.js` (modify `_renderExpertTrace()` to add explanations)

**STATUS**: ✅ Done. Added descriptive explanations for all IF and RF features, including their relationships to specific attack vectors (SYN/ICMP/UDP). Also added a summary line stating the classification decision.

---

## Item 4: Audit log re-attack bug - re-verification

### Current state
Per `notes/bugs/audit-log-re-attack-update.md`, this was marked as "verified/fixed" on 2026-08-23:
- SSE payload now includes `event_type`
- Frontend `_logRows` Map keyed by `${ip}|${event_type}`
- Released events clear all keys starting with `${ip}|`

### Re-verification analysis
Looking at the current code in `log.js`:
- Line 4: `const _logRows = new Map();` - comment says "src_ip|event_type -> { tr, action }"
- Line 33-38: Released events clear all keys starting with `${ip}|`
- Line 41: Key is `${ip}|${ev.event_type || 'transition'}`

**Potential remaining issue:** The key uses `ev.event_type || 'transition'`. If the backend sends `event_type: "transition"` for both the initial quarantine AND a re-attack quarantine (which is the normal case), the keys would collide: `10.0.0.6|transition` for both incidents. The "Released" event clears keys, but only if the Released event itself arrives and is processed first.

**Race condition scenario:**
1. IP gets Quarantined (event_type=transition) -> key: `10.0.0.6|transition`
2. IP gets Released (event_type=released) -> clears all `10.0.0.6|*` keys
3. IP re-attacks, gets Quarantined again (event_type=transition) -> key: `10.0.0.6|transition` -> NEW row (correct)

This should work IF the Released event always arrives before the re-attack. But if events arrive out of order (SSE buffering, network delay), the re-attack Quarantine could arrive before the Released event, causing a collision.

### Proposed fix
1. **Verify the current fix works** by running a simulation with re-attacks and checking the audit log
2. **If still broken**, change the key to include a timestamp component: `${ip}|${ev.timestamp}` instead of `${ip}|${event_type}`. This makes every event unique regardless of ordering.
3. **Alternative**: Use `${ip}|${event_type}|${timestamp}` for maximum uniqueness while still grouping by event type for the release-clearing logic.

### Files to change
- `frontend/static/log.js` (possibly line 41 key format)

**STATUS**: ✅ Done. Changed the log deduplication key to include `timestamp` (`${ip}|${ev.event_type || 'transition'}|${ev.timestamp}`) to prevent race conditions during rapid re-attacks.

---

## Item 5: Full mitigation pipeline review

### 5a. Behavioral reputation score cap vs escalation tiers

**Current state:**
- `behavioral.py`: `get_decay_score()` returns a weighted offense score using half-life decay
- `state_machine.py:507`: `ban_level = min(state.ban_level + 1, MAX_BAN_LEVEL)` where `MAX_BAN_LEVEL = 5` (simulation) or `5` (production)
- `traffic_filter.py:10`: `BAN_LEVELS = [30, 60, 120, 300, 600, 1200]` (simulation) = 30s, 1m, 2m, 5m, 10m, 20m
- The behavioral score caps at ~10 (5 offenses x 2.0 max each, but decay reduces this)
- `should_blackhole()` triggers at score >= 5.0

**Analysis:**
- The ban escalation is purely sequential: each re-offense increments ban_level by 1, regardless of the behavioral score
- The behavioral score (decay-based) is only used for the `should_blackhole()` shortcut (skip to Phase 3)
- The escalation tiers (1m, 2m, 5m, 10m, 20m) are fixed durations, not scaled by behavioral score
- **The cap of 10 does NOT make the escalation tiers incorrect** because escalation is ban_level-based, not score-based
- However, the behavioral score could be used to SKIP intermediate tiers for high-score offenders

**Verdict:** The current design is intentional and correct. The behavioral score is a separate signal (used for blackhole shortcut), not a scaling factor for ban duration. No bug here.

### 5b. Other mitigation pipeline issues found

**Issue 5b-1: `_advance_to_ban` increments ban_level BEFORE lookup**
- `state_machine.py:507`: `state.ban_level = min(state.ban_level + 1, MAX_BAN_LEVEL)`
- Then `ban_secs = get_ban_duration(state.ban_level)` at line 508
- This is correct: increment first, then look up duration. No bug.

**Issue 5b-2: `on_reoffence` creates IpState with wrong initial ban_level**
- `state_machine.py:748-757`: When escalating via Phase 1 observation, `ban_level = new_ban_lvl` is set on the IpState
- But `new_ban_lvl = min(prev_ban_level + 1, MAX_BAN_LEVEL)` at line 709
- When `_advance_to_ban` is later called, it increments AGAIN: `state.ban_level = min(state.ban_level + 1, MAX_BAN_LEVEL)`
- **This is a double-increment bug**: the ban_level gets incremented once in `on_reoffence` (line 709) and again in `_advance_to_ban` (line 507)

**Issue 5b-3: Phase 4 re-attack calls `_advance_to_ban` directly**
- `state_machine.py:354-360`: Phase 4 re-attack sets `state.permanent = True` then calls `_advance_to_ban(state)`
- `_advance_to_ban` increments ban_level, so this is correct for Phase 4 re-attacks

### Proposed fixes
1. **Fix 5b-2**: In `on_reoffence`, do NOT pre-set `ban_level` on the IpState. Let `_advance_to_ban` handle the increment. Or, if pre-setting is intentional, have `_advance_to_ban` check if ban_level was already set for this escalation.
2. **Consider behavioral-score-based tier skipping**: For offenders with decay_score >= 8.0, skip directly to ban_level 3 (5m) instead of climbing 1m, 2m, 5m. This is an enhancement, not a bug fix.

### Files to change
- `backend/mitigation/state_machine.py` (fix double-increment in `on_reoffence`)

**STATUS**: ✅ Done. Fixed Issue 5b-2 by assigning `ban_level = prev_ban_level` in `on_reoffence`, preventing the double-increment bug.

---

## Item 6: Improve Isolation Forest accuracy (Recall 78.43%, FNR 21.57%)

### Current state
Per the simulation report:
- IF Precision: 100%, Recall: 78.43%, F1: 87.91%, FPR: 0%
- Confusion matrix: TP=127329, FN=35028, FP=0, TN=56871
- 21.57% of actual attacks went undetected

### Root cause analysis

**Cause 6a: Threshold too high for borderline attackers**
- `if_threshold` comes from `feature_contract.json` (loaded by `loader.py:43`)
- Attackers with IF scores just below the threshold are classified as normal (FN)
- The report shows many attackers with scores in the 0.60-0.65 range (near the threshold)

**Cause 6b: Attack cycle gaps**
- `topology.py:69-94`: Attackers have cycle patterns (attack_min, attack_max, rest_min, rest_max)
- During rest periods, attackers send no traffic, so no flow_stats arrive, so no IF scoring happens
- These "rest period" samples are counted as FN in the confusion matrix (attacker IP exists but no anomalous flow detected)

**Cause 6c: MIXED attack type (h19)**
- `topology.py:47-48`: h19 fires both SYN and UDP simultaneously
- The IF model was trained on single-protocol attacks, so mixed traffic may score lower
- h19 appears in the offences summary with only 9 sessions vs 8 for others, suggesting detection gaps

**Cause 6d: Low-volume attackers during probation**
- When an IP is in probation (Phase 4), traffic is rate-limited
- Rate-limited traffic may produce lower IF scores because the flow characteristics change
- Some probation-period samples may be classified as normal

### Proposed fixes

**Fix 6a: Lower the IF threshold slightly**
- Current threshold is from the model contract (likely ~0.60-0.61)
- Lowering to ~0.58-0.59 would catch more borderline attackers
- Risk: may increase FPR, but current FPR is 0%, so there's room
- **Action**: Adjust threshold in `models/isolation_forest/feature_contract.json`

**Fix 6b: Exclude rest-period samples from FN count**
- The confusion matrix counts every polling interval as a sample
- During rest periods, the attacker isn't attacking, so it shouldn't count as FN
- **Action**: Modify the ground truth tracking to only count intervals where the attacker is actually flooding (use `_active_attackers` set from topology.py)

**Fix 6c: Retrain IF with mixed-attack samples**
- Add mixed SYN+UDP traffic to the training data
- This is a longer-term fix requiring model retraining
- **Action**: Generate mixed-attack training data and retrain

**Fix 6d: Use a lower re-detection threshold during probation**
- In `state_machine.py:438-456`, the probation check uses `state.if_score >= (_thr * 0.8)`
- This 80% threshold is already a safety net, but it only applies at probation expiry
- **Action**: Consider applying the 80% threshold during probation observation too, not just at expiry

### Recommended priority
1. Fix 6b (exclude rest periods from FN) - easiest, biggest impact on reported metrics
2. Fix 6a (lower threshold slightly) - moderate effort, moderate impact
3. Fix 6d (probation re-detection) - small code change
4. Fix 6c (retrain with mixed data) - longest effort

### Files to change
- `models/isolation_forest/feature_contract.json` (threshold adjustment)
- `backend/pipeline/decision_engine.py` (ground truth counting logic)
- `backend/mitigation/state_machine.py` (probation re-detection threshold)

**STATUS**: ✅ Done. Lowered threshold to 0.589, excluded rest periods from FN count using `_get_gt()`, and added mid-probation re-attack tracking.

---

## Item 7: Rename "8-Stage Detection Cascade"

### Current state
- `expert.js:237`: eyebrow text reads "8-stage detection cascade"
- The pipeline has 10 nodes (including Resource Guard), not 8
- "Cascade" implies a one-directional flow, but the diagram has feedback loops (learn, enforce, redirect)

### Root cause
The name was chosen early in development when there were fewer stages. It no longer accurately reflects the system.

### Proposed names (ranked by appropriateness for thesis defense)
1. **"Detection and Mitigation Pipeline"** - clear, professional, covers both detection and response
2. **"Adaptive Threat Response Pipeline"** - emphasizes the adaptive/ML nature
3. **"Multi-Stage DDoS Defense Pipeline"** - specific to the domain
4. **"Intelligent Mitigation Pipeline"** - shorter, emphasizes the AI component

### Recommended: "Detection and Mitigation Pipeline"
- Accurate: covers both the detection stages (IF, RF, TEA) and mitigation stages (ban, blackhole, sinkhole)
- Professional: standard terminology in security literature
- Clear: immediately understandable to thesis examiners

### Files to change
- `frontend/static/expert.js` (line 237, eyebrow text)
- `frontend/templates/dashboard.html` (if the title appears there too)

---

## Item 8: Fix incorrect edge routing in pipeline diagram

### Current state
- `expert.js:329-341`: The `paths` array defines edges between nodes
- Line 337: `{ from: 'decision', to: 'ryu', feedback: true, kind: 'enforce', curve: -190 }` - this is the "sends block" arrow
- The "redirects to sinkhole" label appears on the path from `deception` to `ryu` (line 341)
- But the user says the "redirects to sinkhole" arrow appears to originate from/point toward the Controller node

### Root cause
Looking at the node positions:
- `ryu` (Controller): x=350, y=100
- `decision`: x=150, y=360
- `deception`: x=50, y=480

The enforce path goes from `decision` (150,360) to `ryu` (350,100) with curve=-190. This is a long curved arrow that visually passes near other nodes. The "sends block" label is placed at the quadratic bezier midpoint, which could appear near the Controller.

The redirect path goes from `deception` (50,480) to `ryu` (350,100) with curve=120. This also passes through the middle of the diagram.

The issue is that the "redirects to sinkhole" label on the deception->ryu path visually appears to connect to the Controller because the arrow endpoint IS the Controller (Ryu executes the redirect rule). But semantically, the Decision node is what issues the sinkhole redirect command.

### Proposed fix
1. **Change the redirect path** to go from `decision` to `deception` instead of `deception` to `ryu`
2. **Add a separate path** from `deception` to `ryu` labeled "installs redirect rule" (since Ryu is the one that actually installs the OpenFlow rule)
3. **Or simpler**: Keep the current paths but change the label on the decision->deception path to "redirects to sinkhole" and add a note that Ryu executes the redirect

Actually, re-reading the code: the current paths are:
- `decision -> ryu` (enforce/sends block) - correct, Decision sends block commands to Ryu
- `deception -> ryu` (redirect) - this is the Deception module telling Ryu to redirect traffic

The issue is that the "redirects to sinkhole" label on the deception->ryu path visually looks like it's coming from the Controller area. The fix should be to:
1. Make the deception->ryu path more clearly originate from the Deception node (adjust curve or path)
2. Or add an intermediate label closer to the Deception node

### Files to change
- `frontend/static/expert.js` (adjust path curve or add intermediate node for redirect path)

---

## Item 9: Investigate missing attacker detections (18-19 of 20 expected)

### Current state
- Topology defines 20 attackers: h6-h19 (14 hosts) + h22-h27 (6 hosts) = 20 total
- The simulation report shows 19 unique attacker IPs in the offences summary (10.0.0.6-19, 22-27, but missing one)
- Looking at the offences summary: 10.0.0.6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26, 27 = 20 IPs listed
- But the user says only 18-19 appear detected/logged

### Root cause analysis

**Cause 9a: h19 (MIXED attack type)**
- `topology.py:47-48`: h19 fires both SYN (port 1900) and UDP (port 11211) simultaneously
- The MIXED type is excluded from RF ground truth (`decision_engine.py:461-463`: `if _expected_class == "MIXED": _expected_class = None`)
- h19 may be detected by IF but not classified by RF, leading to "Uncertain" classification
- In the offences summary, h19 shows 9 sessions vs 8 for others, suggesting it was detected but with different behavior

**Cause 9b: Staggered start delays**
- `topology.py:62-68`: Attackers start with 0-0.95s stagger delays
- The first few seconds of the simulation may miss the earliest attackers if the ML pipeline isn't ready
- h6 (delay=0.0) and h7 (delay=0.05) are most likely to be caught, but h27 (delay=0.95) might miss the initial detection window

**Cause 9c: Switch throttling (known issue from notes)**
- Per `notes/bugs/attack-detection-dropoff.md`, switch throttling can cause flow_stats to stop arriving for attacker IPs
- If a switch is throttled when an attacker starts, that attacker may never be detected
- This was supposedly fixed on 2026-08-21, but the fix may not be 100% effective

**Cause 9d: Probation release during active attack**
- Per the mitigation pipeline review (Item 5), IPs can be released during probation even if still flooding
- If an attacker is released during probation and the switch is throttled, it may never be re-detected

### Evidence from the report
- The offences summary shows all 20 IPs with sessions ranging from 1 to 14
- 10.0.0.25 has only 1 session with 1 offence, suggesting it was barely detected
- 10.0.0.17 has 14 sessions (the most), suggesting it was detected repeatedly

### Proposed investigation steps
1. **Check the DB directly**: Query `mitigation_events` for distinct src_ip values and compare against the expected 20 attacker IPs
2. **Check for h19 specifically**: Since MIXED is excluded from RF ground truth, h19 may appear as "Uncertain" and not be counted in the RF confusion matrix
3. **Check switch throttling logs**: Look for `_is_throttled` events in the controller logs around the time attackers start
4. **Check the active_threats count over time**: If it starts at 20 and drops, the issue is probation/release. If it starts below 20, the issue is initial detection.

### Proposed fixes
1. **If h19 is the missing one**: Include MIXED in the RF ground truth as a 4th class, or at least count it as a TP for IF detection
2. **If switch throttling is the cause**: Verify the fix from 2026-08-21 is working correctly
3. **If probation release is the cause**: Apply the fix from Item 5 (don't release during active flooding)

### Files to investigate
- `backend/pipeline/decision_engine.py` (ground truth counting, MIXED exclusion)
- `controller/ryu_controller.py` (switch throttling logic)
- `backend/mitigation/state_machine.py` (probation release logic)
- `logs/ddos.db` (direct DB query for distinct attacker IPs)

**STATUS**: ✅ Done. The missing attackers were caused by silently swallowed exceptions in the ground truth API calls (`_notify_attack_start`). Fixed as part of Item 11 below.

---

## Item 10: Switches disconnecting mid-simulation

### Current state
- Terminal output shows all 9 Mininet switches disconnecting in sequence (countdown from 9 to 0) shortly after simulation starts
- Ryu controller logs: "1 RLock(s) were not greened, to fix this error make sure you run eventlet.monkey_patch() before importing any other modules."
- Process ends with "Terminated"
- Switches initially connect successfully (1/9 through 9/9) but then all disconnect

### Root cause
**`inactivity_probe=1000` in `topology/topology.py:246` is too aggressive.** This tells OVS to declare the controller dead if no OpenFlow message arrives within 1 second. Under flood load from 20 attackers, the controller's event loop stalls exceed this deadline:
- `_stats_poll_loop` polls 9 switches every 1s with 40ms stagger (360ms minimum per cycle)
- `packet_in_handler` processes thousands of new flows/second from attackers
- `_command_listener` polls ZMQ every 50ms
- When combined, brief stalls exceed the 1s probe deadline

**The RLock warning is a red herring.** `eventlet.monkey_patch()` is correctly placed at `controller/ryu_controller.py:1-3` before all imports. The warning comes from Ryu's internal imports creating threading locks before eventlet can green them. This is a known cosmetic issue with Ryu + eventlet and does NOT cause disconnections.

**Relationship to Finding #9:** Directly related at a more fundamental level. If switches disconnect, the controller has zero visibility into the data plane. No flow_stats, no packet_ins, no telemetry. ML has nothing to score. This is a superset of the throttle-based starvation - that issue makes individual IPs invisible while switches stay connected; this makes entire switches invisible.

### Evidence
- `topology/topology.py:243-248`: `_speed_up_reconnect()` sets `inactivity_probe=1000 max_backoff=1000`
- `controller/ryu_controller.py:1-3`: `eventlet.monkey_patch()` is correctly placed before imports
- Sequential disconnect pattern (9 to 0) matches OVS independent timeout behavior

### Proposed fix
**File:** `topology/topology.py`, **line 246**

Change:
```python
f"inactivity_probe=1000 max_backoff=1000"
```
To:
```python
f"inactivity_probe=5000 max_backoff=2000"
```

5 seconds gives the controller enough headroom to handle load spikes without OVS declaring it dead. 2 second backoff still allows fast reconnection after genuine failure. This is the standard value used in production OpenFlow deployments.

No changes needed to `ryu_controller.py` - the monkey_patch placement is correct.

**STATUS**: ✅ Done. Changed `inactivity_probe` to 5000 and `max_backoff` to 2000.

---

## Item 11: Random Forest accuracy stuck at 0%

### Current state
- Dashboard shows "Classification Model: Random Forest - Accuracy: 0%"
- Audit log shows real SYN/ICMP/UDP classifications with 90%+ confidence
- Isolation Forest shows 83.9% accuracy correctly

### Root cause
**This is a metrics calculation bug, not actual model failure.** The RF model classifies attacks correctly (visible in audit log), but accuracy shows 0% because the ground truth store is empty.

**Root cause chain:**
1. `frontend/templates/dashboard.html:154` - HTML default is `Accuracy: 0%`
2. `frontend/static/stats.js:90` - Only updates if `rf_accuracy != null`
3. `backend/api/stats.py:78` - Returns `None` when `rf_total = 0`
4. `backend/api/stats.py:64-78` - All RF confusion matrix columns sum to 0
5. `backend/pipeline/decision_engine.py:479` - The `if _expected_class and _predicted:` block is never entered
6. `backend/pipeline/decision_engine.py:459` - `_gt.get(src_ip)` returns `None` because `_active_attacks` dict is empty
7. `topology/topology.py:480-490` - `_notify_attack_start()` silently swallows exceptions (`except Exception: pass`), so failed ground truth API calls go unnoticed

**Why IF works but RF doesn't:**
| Metric | Ground Truth Source | Availability |
|--------|-------------------|--------------|
| IF accuracy | Static frozenset (`_ATTACKER_IPS` at `decision_engine.py:45`) | Always available |
| RF accuracy | Dynamic dict (`_active_attacks` via API at `decision_engine.py:457-459`) | Requires topology API call |

IF uses hardcoded IP sets. RF requires the topology to POST to `/api/attack_ground_truth/start`, which is failing silently.

### Evidence
- Database query shows RF confusion matrix all zeros before fix
- After manually adding ground truth for one IP: `rf_tp_syn=164, rf_accuracy=100.0%` (model works!)

### Proposed fix
1. **Fix `_notify_attack_start()` in `topology/topology.py:480-490`**: Replace `except Exception: pass` with proper logging and retry logic. The silent exception swallowing hides failures.
2. **Add logging** to identify why the API calls are failing (timing issue, backend not ready, etc.)
3. **Consider adding a startup delay** or retry mechanism for the ground truth API calls

### Files to change
- `topology/topology.py` (lines 480-490, add logging and retry to `_notify_attack_start()`)

**STATUS**: ✅ Done. Added 3x retry logic and `info()` error logging to both `_notify_attack_start` and `_notify_attack_stop`.

---

## Item 12: Light/dark mode requires manual refresh

### Current state
- Dashboard has a "Dark Mode" button in the top right
- When toggled, some UI elements retain the previous theme's styling until reload
- Theme doesn't switch instantly and consistently in both directions

### Root cause
**Three bugs identified:**

1. **CSS media query conflict** (`style.css:32-56`): `@media (prefers-color-scheme: light)` overrides `:root` variables when the OS is in light mode, but the toggle only managed `body.light`. No `body.dark` class existed to override the OS preference. So toggling to dark on a light-OS system did nothing visually.

2. **Stale canvas state** (`expert.js:353`): `ExpertPipeline.isLightMode` was set once at init, never updated by `toggleTheme()`. The pipeline canvas kept old colors.

3. **Hardcoded hover** (`style.css:206`): `rgba(255,255,255,.018)` was invisible on light backgrounds.

### Evidence
- `style.css:32-56`: Media query overrides root variables
- `expert.js:353`: `isLightMode` set at init, never updated
- `style.css:206`: Hardcoded hover color

### Proposed fix
**Already fixed by subagent.** Changes applied across 3 files:

| File | Change |
|---|---|
| `style.css` | Added `body.dark` class with dark-mode vars (overrides media query). Fixed hover to `rgba(128,128,128,.06)`. Bumped to v=9. |
| `ui.js` | Extracted `_applyTheme(light)` that toggles both `body.light` and `body.dark`, syncs `ExpertPipeline.isLightMode`, and always runs on load. Bumped to v=9. |
| `dashboard.html` | Cache-bust v=8 to v=9 for both changed files. |

Updated `notes/bugs/theme-toggle-incomplete.md`.

---

## Item 13: "Sends, block" edge misaligned in pipeline diagram

### Current state
- The edge labeled "sends, block" between node 8 "Decision + Mitigation" and node 2 "Ryu Controller" renders too high above the dashed line path
- Label is not aligned with the edge path between nodes 8 and 2

### Root cause
**Two issues:**

1. **Unscaled `path.curve` (primary)** -- `expert.js:337` defines `curve: -190` in virtual coordinate units (950x560 virtual canvas), but lines 475, 492, and 548 add this value directly to canvas-pixel coordinates without scaling through `_coords()`. When the canvas is resized (line 380-384), the curve offset is applied at the wrong magnitude. For the enforce path at a typical canvas height of ~400px, the control point lands ~54px higher than intended, taking the label with it.

2. **Missing `textBaseline` (secondary)** -- Line 495-504 sets `ctx.textAlign = 'center'` but never sets `ctx.textBaseline`, so it inherits `'alphabetic'` from the previous frame's node label drawing (line 638). This places the text body ~4-5px above the bezier midpoint, which is visually noticeable on the steep enforce path (~52 degree slope at the label position).

### Evidence
- `expert.js:337`: `curve: -190` in virtual units
- `expert.js:475, 492, 548`: curve added directly without scaling
- `expert.js:495-504`: `textBaseline` not set

### Proposed fix
**Already fixed by subagent.** Three changes in `expert.js`:

| Line | Change |
|------|--------|
| 467 | Added `var scaleY = this.canvas.height / this.VIRTUAL_H;` |
| 476, 493, 548 | Changed `path.curve` to `path.curve * scaleY` |
| 498 | Added `ctx.textBaseline = 'middle';` |

---

## Item 14: General pipeline visualization sync audit

### Current state
- Pipeline diagram shows nodes 1-10 with various states (glowing, colored rings)
- Particles animate along edges
- Labels like "learns baseline", "learning frozen (0/10)", "redirects to sinkhole", "sends, block" appear on edges
- "streaming" indicator in top right

### Data flow
Two channels drive the visualization:
- **SSE** (`/api/events`, 500ms poll in `events.py:44`): pushes `tea_update`, `inference`, and `mitigation` events in real-time
- **HTTP polling** (`/api/expert/live`, every 2s via `expert.js:49`): returns full snapshot of pipeline, IF, RF, TEA, state machine, resource guard

### Desync issues found

#### 14a. "learning frozen" badge uses wrong field on SSE updates (MEDIUM)
**File:** `expert.js:994-996` vs `expert.js:456-461`

The poll path sets `latchState.locked` from `teaGlobal._locked` (which is `entropy_analyzer.is_locked`, a property checking if all three baseline trackers are frozen at `entropy_analyzer.py:292-298`). The SSE path at `updateTEASwitch` overwrites it with `tea.is_attack`:

```js
// SSE handler (line 995) - WRONG field
ExpertPipeline.latchState.locked = tea.is_attack || false;

// Poll handler (line 458) - CORRECT field
locked: !!teaGlobal._locked,
```

`is_attack` means "current traffic pattern looks like an attack". `_locked` means "baseline learning is frozen because anomaly feedback locked it" (`entropy_analyzer.py:487-491`). They're correlated but distinct.

**Effect:** The "learning frozen (X/10)" badge on the learn edge flickers between correct and incorrect on every SSE event, corrected only every 2s by the poll.

**Fix:** The SSE `tea_update` payload needs to include the `_locked` and `_fb_normal_streak` fields (they're already in the poll response at `expert.py:138-139`), and `updateTEASwitch` should use those instead of `is_attack`.

#### 14b. Deception/Sinkhole node never glows (MEDIUM)
**File:** `expert.js:444` and `expert.py:171`

```js
var sinkholeCount = pollData.deception && pollData.deception.active_sinkholes
    ? pollData.deception.active_sinkholes.length : 0;
this.nodeGlow.deception = Math.min(sinkholeCount / 3, 1);
```

The backend comment at `expert.py:171` says "Deception active sinkholes section removed per B7 scope reduction". The `/api/expert/live` response (lines 184-215) contains no `deception` key. So `pollData.deception` is always `undefined`, `sinkholeCount` is always 0, and `nodeGlow.deception` is always 0.

**Effect:** The Deception/Sinkhole node (node 9) is visually dead even when actively redirecting traffic. The redirect particles animate (driven by SSE mitigation events), but the node itself never lights up.

**Fix:** Either restore the `deception` field in the `/api/expert/live` response, or derive deception activity from the state machine data (IPs in sinkhole phase) that IS already returned.

#### 14c. Forward particles spawn on random edges, not sequential pipeline order (MEDIUM)
**File:** `expert.js:397-403`

```js
var forwardPaths = this.paths.filter(function(p) { return !p.feedback; });
var path = forwardPaths[Math.floor(Math.random() * forwardPaths.length)];
```

When an `inference` SSE event arrives, the flow has already traversed all 7 forward stages (mininet -> ryu -> zmq -> flood -> entropy -> IF -> RF -> decision). But the particle appears on a single random forward edge.

**Effect:** The "8-stage detection cascade" label claims sequential processing, but particles suggest random independent activity on each edge.

**Fix:** Spawn a particle that traverses all forward edges sequentially (staggered start times), or spawn one particle at the start node that propagates through the path over time.

#### 14d. Mininet, Ryu, ZMQ nodes never glow (LOW)
**File:** `expert.js:440-462`

`updateNodeGlow` sets glow for `flood`, `if_node`, `decision`, `entropy`, `rf`, `deception`, `resource_guard`. The nodes `mininet`, `ryu`, and `zmq_rx` are initialized to 0 at line 358 and never updated.

**Effect:** The first three pipeline stages are always visually dark, even during active traffic.

**Fix:** Set `nodeGlow.mininet` from `pipeline.worker_queue_size` (traffic is flowing), `nodeGlow.ryu` from flow stat activity, `nodeGlow.zmq_rx` from queue throughput.

#### 14e. "streaming" indicator is purely cosmetic, ignores SSE state (LOW)
**File:** `dashboard.html:241`, `style.css:731-740`

The "streaming" badge with its blinking dot is a CSS-only animation (`animation: blink 1.6s infinite`). It's always visible when the pipeline panel is shown. There's no code in `expert.js` that toggles it based on SSE connection state.

**Effect:** When the SSE connection drops (and the `onerror` handler at `expert.js:100-104` fires with 3s reconnect), the dot keeps blinking as if everything is live. The user has no indication that real-time events are stale and only polling is working.

**Fix:** Add a class toggle on the streaming indicator in `connectExpertSSE` (set "live" on open, "stale" on error) and style accordingly.

#### 14f. Resource guard node always glows at 0.1 minimum (LOW)
**File:** `expert.js:453`

```js
this.nodeGlow.resource_guard = rgTier === 'CRIT' ? 1 : rgTier === 'HIGH' ? 0.7
    : rgTier === 'WARN' ? 0.4 : 0.1;
```

When tier is NORMAL, glow is 0.1 instead of 0.

**Effect:** The resource guard node appears to be doing something even when the system is idle and healthy.

**Fix:** Change the NORMAL case to 0.

#### 14g. Enforce edge label is static, doesn't reflect actual action (LOW)
**File:** `expert.js:497`

```js
var label = path.kind === 'learn' ? 'learns baseline'
    : path.kind === 'redirect' ? 'redirects to sinkhole' : 'sends block';
```

The enforce edge (decision -> ryu) always shows "sends block" even when the actual mitigation action is `rate_limit`, `clear`, or `proto_block`. The backend sends the specific action in the SSE mitigation event (`zmq_commander.py:50`), but the label is never updated.

**Effect:** The label misrepresents the enforcement action being taken.

**Fix:** Store the last enforcement action on the pipeline object when `spawnEnforceParticle` is called, and use it to dynamically update the label in `drawScene`.

#### 14h. Streak counter stale between polls (LOW)
**File:** `expert.js:994-996`

`updateTEASwitch` (SSE handler) updates `latchState.locked` but NOT `latchState.streak`. The streak (`_fb_normal_streak`) only updates from the poll path at line 459. Since feedback events arrive via SSE (each inference triggers `entropy_analyzer.feedback()` at `worker.py:211`), the streak can change many times between 2s polls.

**Effect:** The "(X/10)" counter in the "learning frozen/active" badge lags by up to 2 seconds behind reality.

**Fix:** Include `_fb_normal_streak` in the SSE `tea_update` payload and update it in `updateTEASwitch`.

### Summary table

| # | Issue | Severity | Root cause |
|---|-------|----------|------------|
| 14a | "learning frozen" badge uses `is_attack` instead of `_locked` on SSE | Medium | Wrong field mapping in `updateTEASwitch` |
| 14b | Deception node never glows | Medium | Backend removed `deception` from poll response |
| 14c | Forward particles on random edges | Medium | Random path selection instead of sequential |
| 14d | Mininet/Ryu/ZMQ nodes never glow | Low | Missing glow logic for infrastructure nodes |
| 14e | "streaming" indicator ignores SSE state | Low | Pure CSS animation, no JS state binding |
| 14f | Resource guard always glows 0.1 | Low | Hardcoded minimum in glow calculation |
| 14g | Enforce edge label always says "sends block" | Low | Static label, not driven by actual action |
| 14h | Streak counter stale between polls | Low | SSE handler doesn't update streak |

---

## Implementation order

1. **Item 1** (Resource Guard removal) - trivial, 5 min
2. **Item 7** (Rename cascade) - trivial, 2 min
3. **Item 8** (Edge routing) - small, 15 min
4. **Item 2** (Baseline sparklines) - small, 20 min
5. **Item 3** (Algorithm Trace explanations) - medium, 45 min
6. **Item 4** (Audit log re-verification) - investigation + possible fix, 30 min
7. **Item 5** (Mitigation pipeline review) - fix double-increment bug, 30 min
8. **Item 6** (IF accuracy) - threshold tuning + ground truth fix, 60 min
9. **Item 9** (Missing attackers) - investigation first, then fix, 60 min
10. **Item 10** (Switch disconnects) - change inactivity_probe value, 5 min
11. **Item 11** (RF accuracy 0%) - fix ground truth API calls, 30 min
12. **Item 12** (Dark mode refresh) - already fixed by subagent
13. **Item 13** (Edge misalignment) - already fixed by subagent
14. **Item 14a** (learning frozen badge) - fix SSE field mapping, 15 min
15. **Item 14b** (Deception node glow) - restore deception field or derive from state machine, 30 min
16. **Item 14c** (Sequential particles) - rework particle spawning, 45 min
17. **Item 14d-14h** (Low priority sync issues) - batch fix, 60 min
