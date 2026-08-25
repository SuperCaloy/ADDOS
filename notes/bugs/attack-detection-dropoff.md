---
created: 2026-08-20
last-updated: 2026-08-21
status: verified
tags:
  - bugs
  - backend
  - detection
  - mitigation
---

# Attack Detection Drop-off (20 → ~9)

> [!warning]
> This issue was confirmed against a real simulation run (`logs/ddos.db`, 2026-08-20 11:39-12:28). The drop-off is reproducible and matches the operator's report ("all attackers detected at first, then only ~9 after 10-30 min").

## Summary

All 20 simulated attackers are detected within the first minute, but the **active threat count collapses to ~7-9 within 10-30 minutes** even though every attacker keeps flooding continuously for the entire run. The dashboard's `active_threats` count (which is `len(state_machine.get_active_list()) + len(deception.get_active_list())`) drops, so the operator believes attackers are no longer detected.

## Evidence (from `logs/ddos.db`)

- **Initial detection is complete**: at 11:40-11:41, all 20 attacker IPs (`10.0.0.6-19`, `10.0.0.22-27`) appear in `mitigation_events`.
- **Active count collapses**: the distinct-IPs-per-5-min-bucket count of mitigation events drops from 20 → 3-10 by 11:42 and stays low for the rest of the run.
- **The dominant release reason is `Probation Complete` (97 entries)** vs `Attack Stopped` (3) and `Sinkhole - Unresolved after quarantine` (3).
- **Per-IP churn**: every attacker shows 2-9 "Probation Complete" release cycles, i.e. each IP is repeatedly quarantined → banned → probated → released, never reaching a stable "still attacking" state.
- **End state**: only 7-8 IPs remain in `quarantine_state` (h19 Blackhole permanent; h26/h6/h10/h22/h15/h13 Time Ban), matching the "~9" observation.
- **Late-run scoring** (e.g. `10.0.0.7` at 12:03): `if_score=0.641423` repeated (cache replay), `is_anomaly=1` but **below the `_evaluate_phase1` threshold**, so the IP is never re-escalated.

## Root Cause Chain

The evidence points to a **feedback loop in the Ryu controller's packet-in rate limiter** as the primary mechanism, combined with the backend's probation-clearing path. The sequence is:

1. **`_evaluate_phase1` release logic** (`state_machine.py:410-436`): after the Phase 1 window (10-30 s), an IP is escalated to a ban only if BOTH `if_score >= thr` AND `recent_pps > 1.0`. Otherwise it is released. `recent_pps` is updated unconditionally for Phase 1 IPs via `update_observation` (`decision_engine.py:324-327`), so a genuinely flooding Phase 1 IP normally escalates.

2. **IP escalates to Time Ban (Phase 2)**: once banned, `zmq_receiver.py:201-208` **drops the IP's flow_stats** (only Phase 4 allowed through), so it stops being scored while banned.

3. **Phase 4 probation** (`state_machine.py:507-524`): when the ban TTL expires, the IP moves to Phase 4 for `PROBATION_DURATION` (30 s sim / 300 s prod). The controller installs `rate_limit` so ML can re-score. If ML re-flags → jumps back to ban. If not re-flagged in the window → `_clear("Probation Complete")` at `state_machine.py:403-404` → IP removed from `_states` → drops off `get_active_list()` / `active_threats`.

4. **The re-detection gap (primary bug, observed)**: after `_clear`, the controller sends `resolve_release_action()` which deletes the block rules and installs only a short-lived p5 permit (10 s idle). The attacker is still flooding, so the next table-miss packet triggers `packet_in`. **If that switch is past `_PKT_IN_RATE_LIMIT` (1000 packet-ins/s), the throttled path floods the packet via `PacketOut` WITHOUT installing a forward rule and WITHOUT pushing flow telemetry** (`ryu_controller.py:227-252`, `_handle_ipv4` never runs). No forward rule → no flow entry → no flow_stats for that src_ip → ML never re-scores it → the IP stays invisible for as long as the switch stays throttled (up to tens of minutes; e.g. h7 went undetected 12:04 → 12:29 despite flooding continuously). This is a positive feedback loop: flooding without rule installation keeps generating table-miss packet-ins, sustaining the throttle.

5. **Secondary contributors**:
   - `idle_timeout=60` on the p10 forward rule means a released IP's rule drops quickly; combined with the throttle it is never re-installed.
   - The IF score of a sustained SYN flood sits near the decision boundary (`~0.64`), so re-detection during the brief unscored hold is fragile and depends on flow_stats actually arriving.

The net effect: an IP that is cleared from probation stops being tracked by ML whenever its switch is throttled, its traffic keeps flooding to the server (flooded, un-tracked), and the backend's `active_threats` count drops to the handful of IPs whose switches are below the throttle limit.

## Fix Options (not yet implemented)

1. **Fix the throttle starvation (primary fix, `ryu_controller.py`)**: in the throttled path (`_is_throttled`), stop flooding packets that come from IPs the backend is actively tracking (banned or recently-released). For those, still install the forward rule (or drop them) instead of flooding without a rule, so `flow_stats` keep flowing and ML can re-score. Flooding is the exact behavior that breaks detection: it bypasses the flow table and starves telemetry.

2. **Re-detection on probation regardless of threshold**: in `_evaluate_phase1` / Phase 4 re-detection, escalate back to ban when `is_anomaly` is True AND pps is still elevated, instead of requiring `if_score >= loader.if_threshold`. Use a lower re-offence threshold (or reuse `on_reoffence` escalation logic) so a sustained flood is never released mid-attack.

3. **Score banned IPs during Phase 2/3**: instead of dropping flow_stats at `zmq_receiver.py:201-208`, keep scoring them (cheap) so the ban can be extended or probation can be decided with live evidence. This also removes the "frozen if_score" cache-replay artifact seen at late run times.

Recommended first step: **Option 1**, since it breaks the feedback loop that makes IPs invisible to ML. Option 2 is a cheap safety net on the backend. Option 3 is a deeper pipeline change.

## Related notes

- [[backend/mitigation]]: state machine, probation, `_clear`.
- [[backend/ml-pipeline]]: worker inference cache, flood prefilter, TEA gate.
- [[backend/transport]]: ZMQ receiver Phase 2/3 skip.
- [[controller/ryu-controller]]: packet-in rate limiter.
- [[topology/topology-simulation]]: attacker topology (20 attackers).
- [[bugs/detection-dropoff-after-ban-expiry]]: P12 fix - safety net for still-flooding IPs

## Resolution (2026-08-21)

Three fixes implemented to break the feedback loop:

**Fix 1a (primary, `controller/ryu_controller.py`):** In `_is_throttled`, non-banned IPs under throttle now get a forward rule installed (p10, idle_timeout=60) instead of being flooded. This keeps flow_stats flowing so ML can score/re-score. Banned IPs still get dropped silently. The forward rule installation mirrors the existing `_handle_ipv4` pattern.

**Fix 1b (safety net, `backend/mitigation/state_machine.py`):**
- `update_observation` now accepts Phase 2/3/4 IPs (not just Phase 1), so `recent_pps` and `if_score` stay live during ban and probation.
- In `tick` for Phase 4: before clearing with "Probation Complete", checks if IP is still flooding (`recent_pps > 1.0` AND `if_score >= threshold * 0.8`). If so, re-bans instead of releasing.

**Fix 1c (`backend/transport/zmq_receiver.py`):** Phase 2/3 IPs no longer have their flow_stats dropped entirely. Instead, TEA is skipped (lightweight path) but flow_stats are still submitted to the worker for IF/RF scoring. This eliminates the frozen `if_score` cache-replay artifact.

**Verification needed:** 20-attacker simulation run to confirm `active_threats` stays at ~20 throughout, not dropping to ~9.

## Regression (2026-08-21, same day)

### Symptoms

After ~30+ minutes of continuous runtime with 20 attackers:
- Attacker count degrades from 20 to ~3 active attackers
- Flow stats stop arriving for attacker IPs at various times
- Legit hosts (10.0.0.1-5) continue receiving flow stats throughout

### Root Cause

The prior fixes (1a/1b/1c) were present but introduced a new failure mode:

1. When an IP enters probation, backend sends `clear` then `rate_limit` commands
2. The `rate_limit` command added the IP to `_banned_ips` in the controller
3. In `_is_throttled`, banned IPs get dropped silently (no flow_stats generated)
4. Flow stats stop arriving for the IP, so ML can't re-score it
5. The IP gets released as "Attack Stopped" (recent_pps <= 1.0) or "Probation Complete"
6. The IP disappears from `active_threats`

**Database evidence** (`logs/ddos.db`, run 19:15-20:08):
- Controller CPU: 0-3% (not overloaded)
- Controller memory: stable at ~58MB
- Flow stats for attackers stop at various times (10.0.0.18 at 19:18:09, 10.0.0.25 at 19:18:17, etc.)
- Flow stats for legit hosts continue throughout (last at 20:08:17)
- Only 3 IPs (10.0.0.6, 10.0.0.22, 10.0.0.23) persist until 20:05 with if_scores ~0.637-0.642

### Fix (2026-08-21)

**Fix 2a (primary, `controller/ryu_controller.py:558`):** The `rate_limit` command no longer adds the IP to `_banned_ips`. Only drop actions (`block`, `quarantine`, `redirect`) add to the banned set. This ensures rate_limited IPs are treated as non-banned in `_is_throttled`, so forward rules are installed and flow_stats continue.

**Fix 2b (`backend/mitigation/state_machine.py:26`):** Increased `PROBATION_DURATION` from 30s to 60s for simulation mode. This gives the ML pipeline more time to re-score rate_limited traffic during probation.

### Verification

Run 20-attacker simulation for 60+ minutes and confirm:
- Switch count stays at 9 (1 core + 8 edge)
- Attacker count stays at ~20 (allowing for brief probation windows)
- Flow stats continue arriving for all attacker IPs throughout the run
- No "Attack Stopped" releases for IPs that are still flooding