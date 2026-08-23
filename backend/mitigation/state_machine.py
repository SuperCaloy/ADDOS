import time
import datetime
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.database import writer
from backend.mitigation.traffic_filter import (
    BLACKHOLE_TTL_SECONDS, resolve_phase1_actions, resolve_ban_action, resolve_blackhole_action,
    resolve_release_action,
    get_ban_duration, get_blackhole_ttl, MAX_BAN_LEVEL,
    SINKHOLE_CONFIDENCE_THRESHOLD,
)
from backend.mitigation import behavioral
from backend.config import SIMULATION_MODE

log = logging.getLogger(__name__)

# ── Phase 1 observation durations ─────────────────────────────────────────
PHASE1_DURATION_LOW  = 10.0
PHASE1_DURATION_HIGH = 20.0

# Simulation: 60s watch. Production: 5 min watch.
# 60s gives ML pipeline enough time to re-score rate_limited traffic during probation.
PROBATION_DURATION = 60.0 if SIMULATION_MODE else 300.0
MIN_QUARANTINE_CONFIDENCE = 0.70
CONFIDENCE_LOCK_THRESHOLD = 0.80

PHASE_LABELS = {
    1: "Quarantined",
    2: "Time Ban",
    3: "Blackhole",
    4: "Probation",
}


@dataclass
class IpState:
    src_ip:         str
    phase:          int   = 1
    attack_vector:  str   = "Uncertain"
    if_score:       float = 0.0
    confidence:     float = 0.0
    priority:       str   = "Low"
    phase_entered:  float = field(default_factory=time.monotonic)
    action_taken:   str   = "Quarantined"
    permanent:      bool  = False
    ttl_expires_at: Optional[float] = None
    first_seen:     str   = field(
        default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    ban_level:      int   = 0
    offence_count:  int   = 0
    # Tentative reputation, unconfirmed. Counts hold_ip triggers only.
    # Never written to behavioral DB history, kept separate from offence_count
    # which only reflects confirmed, ML backed offenses.
    sinkhole_flags: int   = 0
    # Updated by decision_engine on each flow result
    # _evaluate_phase1 checks this to avoid escalating a stopped attacker
    recent_pps:     float = 0.0

    def phase_label(self) -> str:
        return PHASE_LABELS.get(self.phase, "Unknown")

    def time_in_phase_sec(self) -> float:
        return time.monotonic() - self.phase_entered

    def phase1_duration(self) -> float:
        # 30s for Uncertain vector, PHASE1_DURATION_HIGH/LOW for known vectors
        if self.attack_vector == "Uncertain":
            return 30.0
        return PHASE1_DURATION_HIGH if self.priority == "High" else PHASE1_DURATION_LOW

    def to_api_dict(self) -> dict:
        d = {
            "src_ip":            self.src_ip,
            "phase":             self.phase_label(),
            "attack_vector":     self.attack_vector,
            "if_score":          round(self.if_score, 4),
            "confidence":        f"{self.confidence * 100:.1f}%",
            "time_in_phase_sec": int(self.time_in_phase_sec()),
            "priority":          self.priority,
            "offence_count":     self.offence_count,
            "sinkhole_flags":    self.sinkhole_flags,
        }
        if self.ttl_expires_at is not None:
            d["ttl_remaining_sec"] = max(0, int(self.ttl_expires_at - time.monotonic()))
        return d


class StateMachine:

    def __init__(self):
        self._lock      = threading.Lock()
        self._states: dict[str, IpState] = {}
        self._commander = None
        # Injected by main.py after deception module starts
        self._deception = None
        # Tentative reputation, survives IpState clears within this run.
        # Not persisted to DB, not mixed with behavioral.py confirmed offenses.
        self._sinkhole_history: dict[str, int] = {}
        # Hold stats — for results/thesis data. Counts outcomes of hold_ip(),
        # not persisted, reset on restart.
        self._hold_stats = {"held": 0, "rescored": 0, "expired_unscored": 0}

    def set_commander(self, commander) -> None:
        self._commander = commander

    def set_deception(self, deception_module) -> None:
        self._deception = deception_module

    # ── Startup restore ───────────────────────────────────────────────

    def restore_from_db(self) -> None:
        rows = writer.load_quarantine_states()
        if not rows:
            return

        log.info("Restoring %d quarantine entries from DB...", len(rows))
        restored = purged = expired = 0
        now_wall = datetime.datetime.now()

        with self._lock:
            for r in rows:
                src_ip       = r["src_ip"]
                permanent    = bool(r.get("permanent", False))
                expires_at   = r.get("block_expires_at")

                if not permanent:
                    # Non-permanent entries are stale after restart — purge
                    self._push_command(src_ip, "clear")
                    writer.delete_quarantine_state(src_ip)
                    log.info("Purged stale entry: %s", src_ip)
                    purged += 1
                    continue

                if expires_at is not None:
                    try:
                        exp_dt      = datetime.datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
                        remaining_s = (exp_dt - now_wall).total_seconds()
                    except ValueError:
                        remaining_s = 0

                    if remaining_s <= 0:
                        # TTL expired while backend was down — release
                        self._push_command(src_ip, "clear")
                        writer.delete_quarantine_state(src_ip)
                        log.info("TTL expired during downtime, released: %s", src_ip)
                        expired += 1
                        continue

                    ttl_expires_at = time.monotonic() + remaining_s
                    ttl_for_cmd    = int(remaining_s)
                else:
                    ttl_expires_at = None
                    ttl_for_cmd    = None

                state = IpState(
                    src_ip         = src_ip,
                    phase          = r["phase"],
                    attack_vector  = r.get("attack_vector", "Uncertain"),
                    if_score       = float(r.get("if_score", 0) or 0),
                    confidence     = float(r.get("confidence", 0) or 0),
                    action_taken   = r.get("action_taken", "Quarantined"),
                    permanent      = permanent,
                    ttl_expires_at = ttl_expires_at,
                )
                self._states[src_ip] = state
                _action_map = {1: "rate_limit", 2: "rate_limit", 3: "block"}
                self._push_command(src_ip, _action_map.get(r["phase"], "rate_limit"),
                                   ttl=ttl_for_cmd)
                restored += 1

        log.info("Restore complete — %d restored  %d purged  %d TTL-expired",
                 restored, purged, expired)

    # ── Detection entry point ─────────────────────────────────────────

    def on_prefilter_trip(self, src_ip: str, correlated: bool) -> str:
        # Fast trigger from flood_prefilter, before IF/RF has scored anything.
        # correlated=True  (2+ protocols at once) -> sinkhole, strong signal.
        # correlated=False (single protocol)       -> quarantine, weaker signal,
        #                                             rate-limit only, real
        #                                             traffic still gets through.
        # IF/RF results that arrive after this go through on_detection() as
        # normal, which sees the state already exists and updates it with
        # real evidence instead of creating a new one or double-dispatching.
        if self._deception and self._deception.is_sinkholes(src_ip):
            return "Sinkhole"

        with self._lock:
            if src_ip in self._states:
                existing = self._states[src_ip]
                if correlated and existing.phase == 1 and existing.action_taken == "Quarantined":
                    self._advance_to_sinkhole(existing)
                    return "Sinkhole"
                return existing.action_taken

            if not correlated:
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 1,
                    attack_vector = "Uncertain",
                    if_score      = 0.0,
                    confidence    = 0.0,
                    action_taken  = "Quarantined",
                    priority      = "Low",
                    offence_count = 0,
                )
                self._states[src_ip] = state
                for _action in resolve_phase1_actions("Low"):
                    self._push_command(src_ip, _action)
                log.info("Prefilter Quarantine: %s (single-protocol trip)", src_ip)
                self._persist(state)
                writer.log_mitigation_event({
                    "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip":          src_ip,
                    "predicted_class": "DDoS",
                    "attack_vector":   state.attack_vector,
                    "confidence":      state.confidence,
                    "priority":        state.priority,
                    "action_taken":    "Quarantined",
                    "if_score":        state.if_score,
                    "phase":           "Phase 1",
                    "is_manual":       False,
                    "event_type":      "transition",
                    "reason":          "prefilter trip",
                })
                return "Quarantined"

        # Correlated — dispatch sinkhole outside the lock, deception has its own.
        if self._deception:
            self._deception.enter_sinkhole(src_ip, "Uncertain", 0.0, 0.0)
        log.info("Prefilter Sinkhole: %s (correlated, multi-protocol trip)", src_ip)
        return "Sinkhole"

    def update_observation(self, src_ip: str, if_score: float, attack_class: str,
                           confidence: float, recent_pps: float) -> None:
        # Refresh live telemetry for a tracked IP without going through
        # the full mitigation-decision path in on_detection. Called on every
        # IF/RF result regardless of the TEA gate, so a Phase 1 entry never
        # freezes just because a given tick got flagged flash crowd.
        # Phase 4 (probation) also gets live updates so tick() can decide
        # whether to re-ban or release based on current evidence.
        with self._lock:
            state = self._states.get(src_ip)
            if state is None or state.phase not in (1, 2, 3, 4):
                return
            state.if_score   = if_score
            state.recent_pps = recent_pps
            if state.phase == 1:
                # Best evidence wins — only overwrite vector/confidence on a
                # stronger read, same rule on_detection already uses.
                if confidence > state.confidence:
                    state.attack_vector = attack_class
                    state.confidence    = confidence
                else:
                    state.confidence = confidence
                self._persist(state)

    def on_detection(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float) -> str:
        # Local variables for post-lock re-offence routing
        _prior_offense = 0
        _prior_ban     = 0

        with self._lock:
            state = self._states.get(src_ip)

            # Permanent manual blackhole — never re-evaluate
            if state and state.permanent and state.ttl_expires_at is None:
                return state.action_taken

            if state is None:
                # Check behavioral DB history for priority and prior offenses
                _prio          = behavioral.assign_priority(
                    if_score, confidence, src_ip,
                    prior_sinkhole_flags=self._sinkhole_history.get(src_ip, 0),
                )
                _prior_offense = behavioral.get_offences(src_ip)
                _prior_ban     = behavioral.get_ban_level(src_ip)

                if _prior_ban > 0:
                    # Known offender — handle via on_reoffence() outside the lock
                    pass

                else:
                    if _prio == "High":
                        # High priority — skip observation, immediate Time Ban
                        ban_lvl  = min(1, MAX_BAN_LEVEL)
                        ban_secs = get_ban_duration(ban_lvl)
                        state = IpState(
                            src_ip        = src_ip,
                            phase         = 2,
                            attack_vector = attack_class,
                            if_score      = if_score,
                            confidence    = confidence,
                            action_taken  = "Time Ban",
                            priority      = _prio,
                            offence_count = 1,
                            ban_level     = ban_lvl,
                            permanent     = True,
                            ttl_expires_at= time.monotonic() + ban_secs,
                        )
                        self._states[src_ip] = state
                        _ban_action, _ban_ttl = resolve_ban_action(ban_secs)
                        self._push_command(src_ip, _ban_action, ttl=_ban_ttl)
                        log.info("High Priority → Immediate Time Ban: %s  conf=%.1f%%  "
                                 "vector=%s  duration=%ds",
                                 src_ip, confidence * 100, attack_class, ban_secs)
                        self._persist(state)
                        writer.log_mitigation_event({
                            "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "src_ip":          src_ip,
                            "predicted_class": "DDoS",
                            "attack_vector":   attack_class,
                            "confidence":      confidence,
                            "priority":        _prio,
                            "action_taken":    f"Time Ban ({ban_secs // 60}m)" if ban_secs >= 60 else f"Time Ban ({ban_secs}s)",
                            "if_score":        if_score,
                            "phase":           "Time Ban",
                            "is_manual":       False,
                            "event_type":      "transition",
                            "reason":          "high priority detection",
                        })
                    else:
                        # Low priority — Phase 1 observation (quarantine)
                        state = IpState(
                            src_ip        = src_ip,
                            phase         = 1,
                            attack_vector = attack_class,
                            if_score      = if_score,
                            confidence    = confidence,
                            action_taken  = "Quarantined",
                            priority      = _prio,
                            offence_count = 0,
                        )
                        self._states[src_ip] = state
                        for _action in resolve_phase1_actions(_prio):
                            self._push_command(src_ip, _action)
                        log.info("Phase 1 Quarantine: %s  conf=%.1f%%  "
                                 "vector=%s  duration=%.0fs",
                                 src_ip, confidence * 100, attack_class,
                                 state.phase1_duration())
                        self._persist(state)

            else:
                # Phase 4 probation — re-attack detected.
                # Skip Phase 1, go straight to next ban level.
                if state.phase == 4:
                    log.info("Probation re-attack: %s — escalating ban", src_ip)
                    state.if_score      = if_score
                    state.attack_vector = attack_class
                    state.confidence    = confidence
                    state.permanent     = True
                    self._advance_to_ban(state)

                else:
                    # Unscored hold getting its first real evidence —
                    # confirmed strong attack escalates immediately instead of
                    # waiting for TTL. Weak/uncertain evidence just backfills.
                    _was_unscored = state.action_taken.startswith(self._UNSCORED_TAG)
                    if _was_unscored:
                        self._hold_stats["rescored"] += 1
                        writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=0, rescored=1)
                    if _was_unscored and attack_class != "Uncertain" and confidence >= 0.70:
                        state.if_score      = if_score
                        state.attack_vector = attack_class
                        state.confidence    = confidence
                        self._advance_to_blackhole(state)
                    else:
                        # Update vector only if new confidence beats prior — best evidence wins
                        _better_evidence = confidence > state.confidence
                        state.if_score   = if_score
                        if _better_evidence:
                            state.attack_vector = attack_class
                            state.confidence     = confidence
                        else:
                            state.confidence = confidence
                        self._persist(state)

            if state is not None:
                return state.action_taken

        # ── Post-lock: re-offence routing ─────────────────────────────
        if _prior_ban > 0:
            self.on_reoffence(
                src_ip             = src_ip,
                if_score           = if_score,
                attack_class       = attack_class,
                confidence         = confidence,
                prev_ban_level     = _prior_ban,
                prev_offence_count = _prior_offense,
            )
            with self._lock:
                s = self._states.get(src_ip)
                return s.action_taken if s else "Re-offence"

        return "Unknown"

    # ── Tick — automatic phase progression ───────────────────────────

    def tick(self) -> None:
        now = time.monotonic()
        with self._lock:
            for src_ip, state in list(self._states.items()):
                # Permanent manual blackhole — never auto-expires
                if state.permanent and state.ttl_expires_at is None:
                    continue

                elapsed = now - state.phase_entered

                if state.phase == 1 and elapsed >= state.phase1_duration():
                    self._evaluate_phase1(src_ip, state)

                elif state.phase == 2:
                    if state.ttl_expires_at and now >= state.ttl_expires_at:
                        if state.action_taken.startswith(self._UNSCORED_TAG):
                            self._hold_stats["expired_unscored"] += 1
                            writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=0, expired_unscored=1)
                            log.info("Hold expired unscored: %s → probation", src_ip)
                        else:
                            # Ban expired — move to probation, unblock traffic.
                            # IP is still watched; re-attack skips Phase 1.
                            log.info("Time ban expired: %s (level %d) → probation",
                                     src_ip, state.ban_level)
                        self._advance_to_probation(src_ip, state)

                elif state.phase == 3:
                    if state.ttl_expires_at and now >= state.ttl_expires_at:
                        log.info("Blackhole TTL expired: %s → releasing", src_ip)
                        self._clear(src_ip, reason="Blackhole TTL Expired")

                elif state.phase == 4 and elapsed >= PROBATION_DURATION:
                    # Safety net: if IP is still flooding during probation,
                    # re-ban instead of releasing. Uses a lower threshold
                    # (80% of normal) so a sustained flood is never released
                    # mid-attack just because its frozen if_score sits slightly
                    # below the decision boundary.
                    from backend.models import loader
                    _thr = loader.if_threshold if loader._loaded else 0.6004
                    _recent_pps = getattr(state, "recent_pps", None)
                    _pps_elevated = (_recent_pps is not None) and (_recent_pps > 1.0)
                    _score_near = state.if_score >= (_thr * 0.8)

                    if _pps_elevated and _score_near:
                        log.info("Probation re-offence: %s still flooding "
                                 "(pps=%.1f, IF=%.4f) — re-banning",
                                 src_ip, _recent_pps, state.if_score)
                        self._advance_to_ban(state)
                    else:
                        self._clear(src_ip, reason="Probation Complete")

        # Also tick the deception module observation windows
        if self._deception:
            self._deception.tick()

    def _evaluate_phase1(self, src_ip: str, state: IpState) -> None:
        # After Phase 1 window: escalate to time ban or release.
        # Checks both IF score AND recent_pps to avoid escalating a stopped attacker.
        # recent_pps is None if no recent flow data → treat as stopped (release)
        from backend.models import loader
        thr = loader.if_threshold if loader._loaded else 0.6004

        recent_pps     = getattr(state, "recent_pps", None)
        score_elevated = state.if_score >= thr
        pps_elevated   = (recent_pps is not None) and (recent_pps > 1.0)

        if score_elevated and pps_elevated:
            if state.attack_vector == "Uncertain" and state.confidence < SINKHOLE_CONFIDENCE_THRESHOLD:
                log.info("Phase1 unresolved: %s conf=%.1f%% — escalating to sinkhole",
                         src_ip, state.confidence * 100)
                self._advance_to_sinkhole(state)
            else:
                # Both signals elevated — attack persisted → escalate
                self._advance_to_ban(state)
        else:
            reason = (
                f"score normalized (IF={state.if_score:.4f} < thr={thr:.4f})"
                if not score_elevated
                else f"traffic stopped (pps={recent_pps:.1f} <= 1.0)"
            )
            log.info("Phase1 complete: %s %s — releasing", src_ip, reason)
            self._clear(src_ip, reason="Attack Stopped")

    def _advance_to_ban(self, state: IpState) -> None:
        # Escalate to Phase 2 time ban.
        # Clear SSE dedup so phase-change event is never silently dropped.
        try:
            from backend.pipeline.decision_engine import _sse_dedup, _sse_lock
            with _sse_lock:
                _sse_dedup.pop(state.src_ip, None)
        except Exception:
            pass

        # Increment ban_level BEFORE lookup — each ban longer than the last
        state.ban_level      = min(state.ban_level + 1, MAX_BAN_LEVEL)
        ban_secs             = get_ban_duration(state.ban_level)
        state.offence_count  = min(state.offence_count + 1, 5)  # offence on escalation
        state.phase          = 2
        state.phase_entered  = time.monotonic()
        state.action_taken   = "Time Ban"
        state.permanent      = True
        state.ttl_expires_at = time.monotonic() + ban_secs

        exp_dt  = datetime.datetime.now() + datetime.timedelta(seconds=ban_secs)
        exp_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        _ban_action, _ban_ttl = resolve_ban_action(ban_secs)
        self._push_command(state.src_ip, _ban_action, ttl=_ban_ttl)
        log.info("Phase 2 Time Ban: %s  level=%d  duration=%ds  expires=%s",
                 state.src_ip, state.ban_level, ban_secs, exp_str)
        self._persist(state, block_expires_at=exp_str)

        ban_label = f"{ban_secs // 60}m" if ban_secs >= 60 else f"{ban_secs}s"
        writer.log_mitigation_event({
            "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":          state.src_ip,
            "predicted_class": "DDoS",
            "attack_vector":   state.attack_vector,
            "confidence":      state.confidence,
            "priority":        state.priority,
            "action_taken":    f"Time Ban ({ban_label})",
            "if_score":        state.if_score,
            "phase":           "Time Ban",
            "is_manual":       False,
        })

    def _advance_to_sinkhole(self, state: IpState) -> None:
        # Quarantine could not resolve this IP after the observation window,
        # still Uncertain, still below confidence threshold. Escalate to
        # sinkhole instead of a blind ban, so it keeps getting observed
        # rather than fully blocked on weak evidence.
        src_ip = state.src_ip
        self._states.pop(src_ip, None)
        writer.delete_quarantine_state(src_ip)
        if self._deception:
            self._deception.enter_sinkhole(src_ip, state.attack_vector,
                                           state.if_score, state.confidence)
        behavioral.record_offense(
            src_ip         = src_ip,
            attack_vector  = state.attack_vector,
            if_score       = state.if_score,
            confidence     = state.confidence,
            priority       = state.priority,
            phase_reached  = state.phase,
            first_seen     = state.first_seen,
            unblock_reason = "Sinkhole - Unresolved after quarantine",
            ban_level      = state.ban_level,
            offence_count  = state.offence_count,
        )
        log.info("Sinkhole (post-quarantine): %s  vector=%s  conf=%.1f%%",
                 src_ip, state.attack_vector, state.confidence * 100)

    def _advance_to_probation(self, src_ip: str, state: IpState) -> None:
        # Move IP from Phase 2 to Phase 4 Probation.
        # Install rate_limit so ML can observe traffic without flood risk.
        # If ML flags re-attack during probation, jumps straight to Phase 2.
        state.phase         = 4
        state.phase_entered = time.monotonic()
        state.action_taken  = "Probation"
        state.permanent     = False
        state.ttl_expires_at = None

        # Remove block rule first, then rate_limit for throttled observation.
        # rate_limit allows traffic so zmq_receiver can score it via ML.
        self._push_command(src_ip, resolve_release_action())
        self._push_command(src_ip, "rate_limit")
        writer.delete_quarantine_state(src_ip)

        log.info("Phase 4 Probation: %s  ban_level=%d  watch=%.0fs",
                 src_ip, state.ban_level, PROBATION_DURATION)

        writer.log_mitigation_event({
            "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":          src_ip,
            "predicted_class": "DDoS",
            "attack_vector":   state.attack_vector,
            "confidence":      state.confidence,
            "priority":        state.priority,
            "action_taken":    "Probation",
            "if_score":        state.if_score,
            "phase":           "Probation",
            "is_manual":       False,
        })

    def _advance_to_blackhole(self, state: IpState) -> None:
        # Escalate to Phase 3 Blackhole — max severity, 1hr TTL.
        # Clear SSE dedup so blackhole event always reaches the audit log.
        try:
            from backend.pipeline.decision_engine import _sse_dedup, _sse_lock
            with _sse_lock:
                _sse_dedup.pop(state.src_ip, None)
        except Exception:
            pass

        state.offence_count  = min(state.offence_count + 1, 5)  # offence on blackhole
        state.phase          = 3
        state.phase_entered  = time.monotonic()
        state.action_taken   = "Blackhole"
        state.permanent      = True
        state.ttl_expires_at = time.monotonic() + get_blackhole_ttl()

        exp_dt  = datetime.datetime.now() + datetime.timedelta(seconds=get_blackhole_ttl())
        exp_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        _bh_action, _bh_ttl = resolve_blackhole_action(get_blackhole_ttl())
        self._push_command(state.src_ip, _bh_action, ttl=_bh_ttl)
        log.info("Phase 3 Blackhole: %s  TTL=%ds  expires=%s",
                 state.src_ip, BLACKHOLE_TTL_SECONDS, exp_str)
        self._persist(state, block_expires_at=exp_str)

        writer.log_mitigation_event({
            "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":          state.src_ip,
            "predicted_class": "DDoS",
            "attack_vector":   state.attack_vector,
            "confidence":      state.confidence,
            "priority":        state.priority,
            "action_taken":    "Blackhole",
            "if_score":        state.if_score,
            "phase":           "Blackhole",
            "is_manual":       False,
        })

    def _clear(self, src_ip: str, reason: str = "Released") -> None:
        state = self._states.pop(src_ip, None)
        self._push_command(src_ip, resolve_release_action())
        writer.delete_quarantine_state(src_ip)
        if state is not None:
            # Terminal event: the lifecycle ledger must show why mitigation ended.
            writer.log_mitigation_event({
                "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip":          src_ip,
                "predicted_class": "DDoS",
                "attack_vector":   state.attack_vector,
                "confidence":      state.confidence,
                "priority":        state.priority,
                "action_taken":    "Released",
                "if_score":        state.if_score,
                "phase":           state.phase_label(),
                "is_manual":       False,
                "event_type":      "released",
                "reason":          reason,
            })
            # behavioral.record_offense writes to DB so reputation survives restarts
            behavioral.record_offense(
                src_ip         = src_ip,
                attack_vector  = state.attack_vector,
                if_score       = state.if_score,
                confidence     = state.confidence,
                priority       = state.priority,
                phase_reached  = state.phase,
                first_seen     = state.first_seen,
                unblock_reason = reason,
                ban_level      = state.ban_level,
                offence_count  = state.offence_count,
            )
        log.info("Cleared: %s  reason=%s", src_ip, reason)

    # ── Re-offence ────────────────────────────────────────────────────

    def on_reoffence(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float,
                     prev_ban_level: int, prev_offence_count: int) -> None:
        # Previously banned IP detected again.
        # Checks weighted offense score first — if >= threshold → blackhole directly.
        # Otherwise escalates ban level by +1.
        with self._lock:
            _prio       = behavioral.assign_priority(if_score, confidence, src_ip)
            new_ban_lvl = min(prev_ban_level + 1, MAX_BAN_LEVEL)

            # Weighted score >= 5.0 → skip ban, go straight to blackhole
            if behavioral.should_blackhole(src_ip, new_ban_lvl):
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 3,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    priority      = _prio,
                    action_taken  = "Blackhole",
                    ban_level     = new_ban_lvl,
                    offence_count = prev_offence_count + 1,
                )
                self._states[src_ip] = state
                self._advance_to_blackhole(state)
                log.info("Re-offence → Blackhole (score threshold): %s  offences=%d",
                         src_ip, state.offence_count)
            elif new_ban_lvl > MAX_BAN_LEVEL:
                # Max ban level exceeded → blackhole
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 3,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    priority      = _prio,
                    action_taken  = "Blackhole",
                    ban_level     = new_ban_lvl,
                    offence_count = prev_offence_count + 1,
                )
                self._states[src_ip] = state
                self._advance_to_blackhole(state)
                log.info("Re-offence → Blackhole (max ban level): %s  offences=%d",
                         src_ip, state.offence_count)
            else:
                # Escalate to next ban level via Phase 1 observation first
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 1,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    priority      = _prio,
                    action_taken  = "Quarantined",
                    ban_level     = new_ban_lvl,
                    offence_count = prev_offence_count + 1,
                )
                self._states[src_ip] = state
                self._push_command(src_ip, "rate_limit")
                log.info("Re-offence → Phase 1 (ban_level=%d next): %s  offences=%d",
                         new_ban_lvl, src_ip, state.offence_count)
                self._persist(state)
                writer.log_mitigation_event({
                    "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip":          src_ip,
                    "predicted_class": "DDoS",
                    "attack_vector":   attack_class,
                    "confidence":      confidence,
                    "priority":        _prio,
                    "action_taken":    "Quarantined",
                    "if_score":        if_score,
                    "phase":           f"Phase 1 — Re-offence #{state.offence_count}",
                    "is_manual":       False,
                })

    # ── Manual operator actions ───────────────────────────────────────

    def manual_release(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip not in self._states:
                return False
            state = self._states.pop(src_ip)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        writer.log_manual_action(
            src_ip,
            "manual_release",
            attack_vector = state.attack_vector,
            confidence    = state.confidence,
            priority      = state.priority,
            if_score      = state.if_score,
            phase         = state.phase_label(),
        )
        writer.log_attack_history(
            src_ip         = src_ip,
            attack_vector  = state.attack_vector,
            if_score       = state.if_score,
            confidence     = state.confidence,
            priority       = state.priority,
            phase_reached  = state.phase,
            first_seen     = state.first_seen,
            unblock_reason = "Manual Release",
        )
        log.info("Manual release: %s", src_ip)
        return True

    def clear_all_non_permanent(self) -> int:
        cleared = 0
        with self._lock:
            to_remove = [
                ip for ip, s in self._states.items()
                if not s.permanent or s.ttl_expires_at is not None
            ]
            for ip in to_remove:
                self._push_command(ip, "clear")
                writer.delete_quarantine_state(ip)
                del self._states[ip]
                cleared += 1
        if cleared:
            log.info("Cleared %d non-permanent/TTL entries", cleared)
        return cleared

    def manual_block(self, src_ip: str) -> bool:
        # Permanent manual blackhole — no TTL
        with self._lock:
            state = self._states.get(src_ip)
            if state is None:
                state = IpState(
                    src_ip         = src_ip,
                    phase          = 3,
                    action_taken   = "Blackhole",
                    permanent      = True,
                    ttl_expires_at = None,
                )
                self._states[src_ip] = state
            else:
                state.phase          = 3
                state.phase_entered  = time.monotonic()
                state.action_taken   = "Blackhole"
                state.permanent      = True
                state.ttl_expires_at = None
            self._persist(state, block_expires_at=None)
        self._push_command(src_ip, "block", ttl=None)
        writer.log_manual_action(
            src_ip,
            "manual_block",
            attack_vector = state.attack_vector,
            confidence    = state.confidence,
            priority      = state.priority,
            if_score      = state.if_score,
            phase         = state.phase_label(),
        )
        log.info("Manual blackhole (permanent): %s", src_ip)
        return True

    _UNSCORED_TAG = "Holding (unscored"

    def hold_ip(self, src_ip: str, reason: str = "unscored", ttl_s: float = 15.0) -> bool:
        # Temporary mitigation for a flagged IP that could not be scored in time,
        # even after priority retry. Not a blind permanent block:
        # - Uses real evidence that exists (flood prefilter flag), not a fake score.
        # - TTL bound, auto releases to probation via tick() if never scored.
        # - Real IF/RF score, if it arrives later, updates this state through
        #   on_detection(), and escalates early to Blackhole if confirmed strong.
        with self._lock:
            state = self._states.get(src_ip)
            if state is not None and state.permanent and state.ttl_expires_at is None:
                # Already a real manual block — do not downgrade it.
                return False
            action_label = f"{self._UNSCORED_TAG}, {reason})"
            _flag_count = self._sinkhole_history.get(src_ip, 0) + 1
            self._sinkhole_history[src_ip] = _flag_count
            self._hold_stats["held"] += 1
            writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=0, held=1)
            if state is None:
                state = IpState(
                    src_ip         = src_ip,
                    phase          = 2,
                    attack_vector  = "Uncertain",
                    if_score       = 0.0,
                    confidence     = 0.0,
                    action_taken   = action_label,
                    permanent      = True,
                    ttl_expires_at = time.monotonic() + ttl_s,
                    sinkhole_flags = _flag_count,
                )
                self._states[src_ip] = state
            else:
                state.phase          = 2
                state.phase_entered  = time.monotonic()
                state.action_taken   = action_label
                state.permanent      = True
                state.ttl_expires_at = time.monotonic() + ttl_s
                state.sinkhole_flags = _flag_count
            self._persist(state)
        writer.log_mitigation_event({
            "timestamp":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":          src_ip,
            "predicted_class": "DDoS",
            "attack_vector":   state.attack_vector,
            "confidence":      state.confidence,
            "priority":        state.priority,
            "action_taken":    action_label,
            "if_score":        state.if_score,
            "phase":           "Phase 2",
            "is_manual":       False,
            "event_type":      "transition",
            "reason":          reason,
        })
        self._push_command(src_ip, "rate_limit", ttl=int(ttl_s))
        log.warning("Holding %s (unscored, reason=%s, ttl=%.0fs)", src_ip, reason, ttl_s)
        return True

    def get_hold_stats(self) -> dict:
        # Results data: how many IPs went through hold_ip, how many got
        # rescored with real evidence before TTL, how many expired unscored.
        with self._lock:
            return dict(self._hold_stats)

    # ── API helpers ───────────────────────────────────────────────────

    def get_active_list(self) -> list[dict]:
        with self._lock:
            rows = [s.to_api_dict() for s in self._states.values()]
        rows.sort(key=lambda r: r["if_score"], reverse=True)
        return rows

    def is_active(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._states

    # ── Internal ─────────────────────────────────────────────────────

    def _persist(self, state: IpState, block_expires_at: Optional[str] = None) -> None:
        writer.save_quarantine_state(
            src_ip           = state.src_ip,
            phase            = state.phase,
            attack_vector    = state.attack_vector,
            if_score         = state.if_score,
            confidence       = state.confidence,
            action_taken     = state.action_taken,
            permanent        = state.permanent,
            block_expires_at = block_expires_at,
        )

    def _push_command(self, src_ip: str, action: str,
                      ttl: Optional[int] = None) -> None:
        if self._commander:
            cmd = {"action": action, "src_ip": src_ip}
            if ttl is not None:
                cmd["ttl"] = ttl
            self._commander.send(cmd)


# Module-level singleton
state_machine = StateMachine()


def start_tick_thread() -> None:
    def _loop():
        while True:
            time.sleep(1.0)
            state_machine.tick()

    t = threading.Thread(target=_loop, name="sm-tick", daemon=True)
    t.start()