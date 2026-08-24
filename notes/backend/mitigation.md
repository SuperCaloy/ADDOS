---
created: 2026-08-19
last-updated: 2026-08-21
status: verified
tags:
  - backend
  - mitigation
---

# Mitigation System

Seven modules under `backend/mitigation/`. The heart is the per-IP **state machine**; deception, behavioral reputation, resource guard, and traffic filter all plug into it.

## State machine: `mitigation/state_machine.py`

Per-IP `IpState` dataclass: `src_ip`, `phase` (1-4), `attack_vector`, `if_score`, `confidence`, `priority`, `phase_entered`, `action_taken`, `permanent`, `ttl_expires_at`, `first_seen`, `ban_level`, `offence_count`, `sinkhole_flags`, `recent_pps`.

### Phases

| Phase | Name | Behavior |
|---|---|---|
| 1 | **Quarantined** | Observation + rate-limit only. `PHASE1_DURATION_LOW=10s` / `HIGH=20s` / 30s for Uncertain |
| 2 | **Time Ban** | Full block with escalating duration |
| 3 | **Blackhole** | Full block, 1h TTL |
| 4 | **Probation** | Watched, rate-limited (30s sim / 300s prod) |

### Entry points

- `on_prefilter_trip(src_ip, correlated)`: fast trigger before ML evidence. Correlated (2+ protocols) → **sinkhole**; single protocol → immediate Phase 1 quarantine with rate-limit.
- `on_detection(src_ip, if_score, attack_class, confidence)`: ML-confirmed entry. New IPs check behavioral DB history; High priority → immediate Time Ban (skips observation); Low → Phase 1. Existing unscored holds get rescored (strong evidence → blackhole); probation re-attack → escalate ban.
- `on_reoffence(...)`: returning offender: weighted offense score ≥ 5.0 or ban overflow → direct blackhole; else escalate ban level.
- `hold_ip(src_ip, reason, ttl_s)`: temporary Phase-2-style hold for unscored-but-flagged IPs; TTL-bound, auto-releases to probation; real scores can arrive later and escalate.

### Tick loop

`tick()` (1s loop) drives transitions: Phase 1 expiry → `_evaluate_phase1()` (escalate to ban if `if_score >= threshold` AND `recent_pps > 1.0`; unresolved Uncertain → sinkhole; else release) → Phase 2 expiry → probation → Phase 3 expiry → clear → Phase 4 expiry → clear. Also ticks the deception module.

### Other

- Manual ops: `manual_release`, `manual_block` (permanent blackhole), `clear_all_non_permanent`.
- `restore_from_db()`: re-issues FlowMods on startup for permanent entries with valid TTLs.
- Commands via `_push_command()` → `commander.send(...)`.
- Singleton `state_machine`; `start_tick_thread()` runs the loop.

### Lifecycle ledger emission points (added 2026-08-21)

Every mitigation lifecycle event lands in `mitigation_events` with `event_type` + `reason` ([[decisions/mitigation-event-logging-strategy]]):

- transition: prefilter trip quarantine, hold_ip hold, Phase 1 escalation to Time Ban, Probation entry, Blackhole entry, re-offence Phase 1, high-priority immediate Time Ban ("high priority detection"), sinkhole entry.
- released: `_clear()` with the actual reason ("Attack Stopped", "Blackhole TTL Expired", "Probation Complete"); sinkhole release ("traffic stopped" / "confidence unresolved" / "manual release" / "resource guard CRIT").
- detected: one per phase entry, written by decision_engine's `_should_log_detection()` gate; carries detection_ms/mitigation_ms.
- manual: operator actions via `log_manual_action()`.

## Deception (sinkhole): `mitigation/deception.py`

- `SINKHOLE_IP = "10.0.0.21"` (silent dummy host h21), observation window 30s, escalation PPS threshold 1.0.
- `enter_sinkhole()`: registers a `SinkholeEntry` + sends a `redirect` FlowMod to the sinkhole IP; logs a mitigation event.
- Live telemetry refresh: `update_pps()`, `update_score()` (called by decision engine).
- `tick()` → `_evaluate()`: after observation window, escalate to Phase 1 (`escalate_fn` → `state_machine.on_detection`) if traffic still active AND (confidence ≥ 0.70 OR cumulative sinkhole time hits `SINKHOLE_MAX_TOTAL_SECONDS = 90`); otherwise release.

> [!warning] `redirect` is not implemented in the controller
> The backend sends `{"action": "redirect"}` but `ryu_controller.py` has **no `redirect` branch**: the sinkhole command is silently ignored at the OpenFlow level. See [[known-issues/known-issues]].

## Behavioral reputation: `mitigation/behavioral.py`

- `record_offense(...)`: writes completed offense to `ip_attack_history`.
- Decayed score: half-life 24h; each offense = `2.0 * 0.5^(hours/24)`.
- `should_blackhole(src_ip, current_ban_level)`: true if decayed score ≥ `BLACKHOLE_OFFENSE_THRESHOLD = 5.0`.
- `assign_priority(...)`: High if: `if_score >= 0.75` AND `conf >= 0.80`; repeat offender (2+); persistent (decay ≥ 3.0); tentative (3+ sinkhole flags).

## Resource guard: `mitigation/resource_guard.py`

Protects controller health (polls every `GUARD_POLL_INTERVAL = 2.0s`):

- **WARN** (CPU 85 / MEM 70): log only.
- **HIGH** (CPU 95 / MEM 85): throttle detection rate to 20ms after 2 consecutive readings.
- **CRIT** (CPU 99 / MEM 95): install **OVS packet-in rate-limit rules** via ZMQ `proto_block`; reinstalls if attack protocol changes mid-CRIT.
- `set_attack_proto()` maps RF class → `nw_proto` (ICMP=1, TCP=6, UDP=17).
- **ML is never paused**: `is_paused` always False.

## Traffic filter: `mitigation/traffic_filter.py`

Action policy + durations.

- Ban levels: sim `[30, 60, 120, 300, 600, 1200]s`; prod `[120, 300, 600, 1800, 3600, 86400]s`.
- `BLACKHOLE_TTL_SECONDS = 3600`; `RATE_LIMIT_PPS = 1000` (sim) / 5000 (prod).
- Action constants sent verbatim to Ryu: `quarantine` (priority-90 drop), `rate_limit` (priority-80 meter), `block` (priority-100 drop), `redirect` (priority-85 to sinkhole), `clear`.
- `should_sinkhole(attack_vector, confidence, phase)`: Uncertain vector + conf < 0.70 and phase < 2.

## ZMQ commander: `mitigation/zmq_commander.py`

Outbound command channel. PUSH socket to `ZMQ_COMMAND_ADDR` (5556), `SNDTIMEO=500ms`, `LINGER=0`. `send()` JSON-encodes + NOBLOCK; drops silently if Ryu offline (`zmq.Again`), reconnects after 3s.

## Monitor: `mitigation/monitor.py`

- `_get_ctrl_metrics()`: finds `ryu-manager` process + children via psutil (cached objects for accurate `cpu_percent`).
- `start()` loop: every ~1s (5 sub-polls for hping3 attack windows) samples backend + controller CPU/mem, pps; determines `is_attack` (ground truth) and `is_mitigating`; writes `writer.log_system_metrics(...)`.

## Related notes

- [[backend/ml-pipeline]]: the detection side feeding this system.
- [[controller/ryu-controller]]: where mitigation rules are installed.
- [[overview/architecture]]: wiring of singletons.