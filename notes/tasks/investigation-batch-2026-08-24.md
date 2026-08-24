---
created: 2026-08-24
last-updated: 2026-08-24
status: done
area: [backend, frontend, mitigation, pipeline, controller]
---

# Investigation Batch 2026-08-24

Root cause findings and fix plans for 4 issues reported by the user.

## Issue 1: Behavioral Score Strategy

### Findings

There is **no cap at 10 anywhere in the codebase**. The current system has redundant scores:

| Score | Type | Purpose | Issue |
|-------|------|---------|-------|
| `reputation_score` (decay) | Float, unbounded | `should_blackhole()` | No cap, threshold at 5.0 |
| `offence_count` | Integer, capped at 5 (in 2 of 3 paths) | Display "Re-offence #N" | **Redundant with ban_level** |
| `offense_total_count` | Integer, raw count | Display only | Not used for decisions |
| `ban_level` | Integer, 1-6 | Ban duration escalation | Works correctly |

### Final Strategy (user decision)

**Option A: Simplify to 3 scores**

| Score | Purpose | Cap | Display |
|-------|---------|-----|---------|
| `ban_level` | Drives ban duration (2m → 24h) | 6 | "Ban Level: 3/6" |
| `reputation_score` (decay) | Triggers blackhole at 10.0 | 10.0 | "Reputation: 7.2/10" |
| `offense_total_count` | Lifetime attack history | None | "Lifetime Attacks: 12" |

**Remove `offence_count`** -- it is redundant with `ban_level`.

**Decay score semantics:**
- +2.0 per offense, 24h half-life, cap at 10.0
- **5 rapid attacks = 10.0 = blackhole** (max persistence)
- After 24h: 5 offenses decay to 5.0 (half the cap)
- After 48h: 5 offenses decay to 2.5 (quarter cap)
- Blackhole threshold: **10.0** (only at max persistence)

**Escalating time bans (unchanged):**
- Each re-offense increments `ban_level` (1 → 6)
- Ban duration: 30s → 60s → 120s → 300s → 600s → 1200s (sim)
- Ban duration: 2m → 5m → 10m → 30m → 1h → 24h (prod)
- After 6 bans, if decay score < 10 → released and starts over
- If decay score reaches 10 → blackhole

### Fix Plan

- [ ] **Remove `offence_count`** from IpState dataclass (`state_machine.py:55`)
- [ ] **Remove `offence_count`** from DB schema (`db.py:213`) -- or keep for backward compat, ignore in code
- [ ] **Remove `offence_count`** from all API responses (`ip_detail.py`, `expert.py`, `mitigation.py`)
- [ ] **Remove `offence_count`** increments in `_advance_to_ban()` (`state_machine.py:531`) and `_advance_to_blackhole()` (`state_machine.py:646`)
- [ ] **Fix `on_reoffence()`** (`state_machine.py:794`) -- remove `offence_count = prev_offence_count + 1`
- [ ] **Add cap at 10.0** to `writer.py:462` for reputation_score
- [ ] **Change `BLACKHOLE_OFFENSE_THRESHOLD`** from 5.0 to 10.0 in `behavioral.py:10`
- [ ] **Display `offense_total_count`** as "Lifetime Attacks" in IP details
- [ ] **Display `reputation_score`** as "Reputation: X/10" in IP details
- [ ] Verify with simulation that blackhole triggers at 5 rapid attacks

---

## Issue 2: Only 15-18 Attackers Actually Attacking

### Findings

**All 20 attackers DO generate traffic.** The issue is NOT in traffic generation.

- `topology/topology.py:31-32` -- 20 attacker IPs defined in `_ATTACKER_NUMS`
- `topology/topology.py:553-578` -- `launch_attack()` starts all 20 via `_attacker_cycle_worker()` threads with watchdog restart
- Each attacker runs `hping3` in continuous `--flood` mode
- User confirmed using `start_mixed_campaign()` which starts all 20 attackers

**This is a detection/pipeline drop-off issue**, not a generation issue. The same root cause as the previously documented bug in [[bugs/attack-detection-dropoff]].

### Root Cause Chain

1. IP enters probation (Phase 4) after ban expires
2. Probation completion check (`state_machine.py:453-471`) releases IP if `recent_pps <= 1.0` or `if_score < threshold * 0.8`
3. After release, controller installs short-lived p5 permit (10s idle)
4. **Specific bug:** In `ryu_controller.py:258`, when dst MAC is unknown, `out_port` defaults to `OFPP_FLOOD`. The check `if out_port != ofp.OFPP_FLOOD:` fails, so no forward rule is installed. The packet falls through to `self._flood()` at line 276, which floods without creating a flow entry.
5. No forward rule = no flow entry = no flow_stats = ML never re-scores the IP
6. The IP stays invisible to the backend indefinitely

The prior fixes (1a/1b/1c, 2a/2b from the existing note) addressed parts of this but the issue persists because:
- The throttle path still floods when dst MAC is unknown (the specific bug above)
- The probation re-ban threshold (`if_score >= threshold * 0.8`) may be too strict for SYN floods near the decision boundary (~0.64)

### Fix Plan

- [x] **Primary fix:** In `ryu_controller.py:258-272`, when dst MAC is unknown under throttle, install a forward rule with `OFPP_NORMAL` output instead of falling through to flood. This lets the switch forward normally while still creating a flow entry for flow_stats.
- [ ] **Safety net:** Lower the probation re-ban threshold or use `is_anomaly` + elevated pps as the re-ban criterion instead of requiring `if_score >= threshold * 0.8`
- [ ] **Optional:** Consider scoring banned IPs during Phase 2/3 so the ban can be extended with live evidence
- [ ] Verify with a 20-attacker simulation run that `active_threats` stays at ~20

---

## Issue 3: Active States Panel -- Cap Visible Rows, Allow Scroll

### Findings

- **Render function**: `frontend/static/expert.js:1131-1147` (`renderMitigationPanel`)
- **Current behavior**: All states rendered at once via `activeIPs.forEach()` loop. No row limit.
- **Container CSS**: `frontend/static/style.css:487-497` (`.terminal-feed`)
  - `height: auto` -- grows unbounded
  - `overflow-y: auto` -- scroll exists but never triggers since height is unbounded
  - `flex-grow: 1` -- expands to fill parent
- **Backend**: `GET /api/expert/live` in `backend/api/expert.py:48` returns all active IP states. No hard cap in `state_machine.py`.

### Root Cause

`height: auto` on `.terminal-feed` means the panel grows to fit all rows. `overflow-y: auto` is set but never activates because there is no height constraint to trigger scrolling.

### Fix Plan

- [ ] **CSS fix:** In `style.css:487-497`, change `height: auto` to `max-height: calc(15 * 25px + 32px)` (15 rows at ~25px each + 32px padding). Keep `overflow-y: auto` (already present).
- [ ] **JS enhancement:** In `expert.js:1131`, cap rendering at 100 entries max with `activeIPs.slice(0, 100)` and show a "Showing X of Y" counter
- [ ] **Optional backend cap:** Add `MAX_ACTIVE_STATES = 100` constant in `state_machine.py` to limit memory if needed

---

## Issue 4: TEA Verdict Inconsistency (Uncertain vs Normal During Attacks)

### Findings

Four issues found:

**A. Per-IP verdict (`_IpEntropyProfile.verdict()`) uses different logic than global gate**
- `entropy_analyzer.py:231-271` -- per-IP verdict uses PPS trend/entropy analysis, NOT the variance-collapse gate
- Returns "uncertain" when `pps_samples < IP_PROFILE_MIN_SAMPLES` (line 232-233) or when neither rising+repetitive nor declining+low_mean conditions are met (line 270)
- This is a **separate code path** from the global `is_attack_pattern` (OR of size/intensity/proto collapse at line 400)
- The per-IP verdict is used in `zmq_receiver.py` for per-IP decisions

**B. Frontend verdict display is binary**
- `expert.js:725-731` -- shows only "Anomaly" (when `is_attack=true`) or "Normal" (everything else)
- No "Uncertain" state displayed. During learning phase or when TEA returns `is_attack_pattern=false`, the frontend shows "Normal" even though TEA may actually be uncertain
- This is misleading -- the user sees "Normal" when TEA is actually still learning or undecided

**C. 1-second cache staleness**
- `entropy_analyzer.py:305` -- TEA result is cached for 1 second. All flows processed within that window get the same cached verdict
- If an attack starts mid-window, the first second of flows gets the pre-attack verdict

**D. Dead code in confidence assignment**
- `entropy_analyzer.py:414` -- `elif size_collapsed or intensity_collapsed or proto_collapsed:` is unreachable because `is_attack_pattern` on line 400 already uses the same OR condition. This branch can never execute.

### Root Cause Classification

This is primarily a **feature issue** (per-IP verdict uses different logic than global gate, and the frontend collapses three states into two) combined with a **timing issue** (1s cache + learning phase).

### Fix Plan

- [ ] **Frontend fix:** In `expert.js:725-731`, show three states based on TEA data:
  - "Anomaly" when `is_attack=true` (red)
  - "Uncertain" when `is_attack=false` AND `confidence="low"` (yellow)
  - "Normal" when `is_attack=false` AND `confidence` is "moderate" or "high" (green)
- [ ] **Dead code cleanup:** Remove unreachable `elif` at `entropy_analyzer.py:414`
- [ ] **Optional:** Reduce cache window from 1s to 500ms for faster attack onset detection
- [ ] **Optional:** Align per-IP verdict logic with global gate, or document why they differ
- [ ] Verify with simulation that TEA consistently flags attacker traffic

---

## Priority Order

1. **Issue 2** (attacker dropoff) -- highest impact, affects detection of active threats. Primary fix is in controller throttle path.
2. **Issue 4** (TEA inconsistency) -- high impact, affects detection accuracy. Frontend fix to show 3 states.
3. **Issue 1** (score cap) -- medium impact, affects behavioral escalation correctness. Cap reputation_score at 10.0, fix offence_count cap in on_reoffence.
4. **Issue 3** (Active States scroll) -- low impact, UI polish. CSS fix for max-height.

## See Also

- [[tasks/regression-fix-plan-2026-08-24]]: comprehensive regression fix plan covering all known bugs
