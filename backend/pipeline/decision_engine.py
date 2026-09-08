import time
import logging
import threading
import datetime
import collections
from backend.mitigation.state_machine import state_machine, _build_mitigation_event, _build_sse_event
from backend.mitigation.deception import deception


def _build_tea_result(flow_stats: dict) -> dict:
    fs = flow_stats or {}
    return {
        "is_flash_crowd":    fs.get("tea_flash_crowd", False),
        "is_attack_pattern": fs.get("tea_attack_pattern", False),
        "confidence":        fs.get("tea_confidence", "low"),
        "is_learned":        fs.get("tea_is_learned", False),
    }


def _compute_rf_confusion(expected_class: str, attack_class: str) -> dict:
    _class_map = {"SYN Flood": "SYN", "ICMP Flood": "ICMP", "UDP Flood": "UDP"}
    _predicted = _class_map.get(attack_class)
    res = {
        "rf_tp": 0, "rf_fp": 0, "rf_tn": 0, "rf_fn": 0,
        "rf_tp_syn": 0, "rf_fp_syn": 0, "rf_tn_syn": 0, "rf_fn_syn": 0,
        "rf_tp_icmp": 0, "rf_fp_icmp": 0, "rf_tn_icmp": 0, "rf_fn_icmp": 0,
        "rf_tp_udp": 0, "rf_fp_udp": 0, "rf_tn_udp": 0, "rf_fn_udp": 0,
        "rf_syn_as_icmp": 0, "rf_syn_as_udp": 0,
        "rf_icmp_as_syn": 0, "rf_icmp_as_udp": 0,
        "rf_udp_as_syn": 0, "rf_udp_as_icmp": 0,
    }
    if expected_class and _predicted:
        if _predicted == expected_class:
            res["rf_tp"] = 1
            if expected_class == "SYN":
                res["rf_tp_syn"] = 1
                res["rf_tn_icmp"] = 1
                res["rf_tn_udp"] = 1
            elif expected_class == "ICMP":
                res["rf_tp_icmp"] = 1
                res["rf_tn_syn"] = 1
                res["rf_tn_udp"] = 1
            elif expected_class == "UDP":
                res["rf_tp_udp"] = 1
                res["rf_tn_syn"] = 1
                res["rf_tn_icmp"] = 1
        else:
            res["rf_fp"] = 1
            res["rf_fn"] = 1
            mis = (expected_class, _predicted)
            if mis == ("SYN", "ICMP"):
                res["rf_syn_as_icmp"] = 1
            elif mis == ("SYN", "UDP"):
                res["rf_syn_as_udp"] = 1
            elif mis == ("ICMP", "SYN"):
                res["rf_icmp_as_syn"] = 1
            elif mis == ("ICMP", "UDP"):
                res["rf_icmp_as_udp"] = 1
            elif mis == ("UDP", "SYN"):
                res["rf_udp_as_syn"] = 1
            elif mis == ("UDP", "ICMP"):
                res["rf_udp_as_icmp"] = 1
    elif expected_class and not _predicted:
        res["rf_fn"] = 1
        if expected_class == "SYN":
            res["rf_fn_syn"] = 1
        elif expected_class == "ICMP":
            res["rf_fn_icmp"] = 1
        elif expected_class == "UDP":
            res["rf_fn_udp"] = 1
    return res


def _merge_confidence(locked: tuple, current: tuple) -> tuple:
    locked_conf, locked_class = locked
    cur_conf, cur_class = current
    if locked_class == "Uncertain" and cur_class != "Uncertain" and cur_conf >= locked_conf:
        return current
    elif cur_conf < locked_conf:
        return (locked_conf, locked_class)
    else:
        return current
from backend.database import writer
from backend.pipeline import worker
from backend.pipeline.flood_prefilter import flood_filter
from backend.pipeline.entropy_analyzer import entropy_analyzer
from backend.models import loader
from backend.config import ML_ENABLED

log = logging.getLogger(__name__)


# Real packet_count when present, else falls back to pps estimate.
def _estimate_pkt_count(flow_stats: dict) -> int:
    fs  = flow_stats or {}
    raw = fs.get("packet_count")
    if raw is not None:
        return max(int(raw), 1)
    pps = float(fs.get("packet_count_per_second", 0.0))
    return max(int(round(pps)), 1)


_lock = threading.Lock()

# Confidence lock - keeps highest seen confidence+attack_class per IP
# Only updates if new confidence > locked value
_conf_lock: dict[str, tuple[float, str]] = {}
_conf_lock_mutex = threading.Lock()

_LEGIT_HOST_IPS: frozenset = frozenset(
    f"10.0.0.{i}" for i in range(1, 16)
)

# Attacker hosts: h16-h25 (per topology.py).
# h26 (server) and h27 (sinkhole) are excluded on purpose.
_ATTACKER_IPS: frozenset = frozenset(
    f"10.0.0.{i}" for i in range(16, 26)
)

_stats = {
    "total_packets":       0,
    "malicious_dropped":   0,   # ML events classified as malicious
    "actual_pkts_dropped": 0,   # real OVS physical drops from dropped_delta messages
    "normal_packets":      0,
    # Dedicated legit counter - incremented directly when IF says normal.
    # Avoids subtraction (raw_total - dropped) which breaks when attackers dominate.
    "normal_forwarded":    0,
    "false_positives":     0,
    "ml_processed":        0,
    "total_latency_ms":    0.0,
    "latency_samples":     0,
}

# Rolling detection_ms samples for percentile reporting (observability).
_latency_lock = threading.Lock()
_latency_samples_ms: collections.deque = collections.deque(maxlen=2000)
_latency_by_origin: dict[str, collections.deque] = {
    "full":     collections.deque(maxlen=2000),
    "low_rate": collections.deque(maxlen=2000),
    "cached":   collections.deque(maxlen=2000),
}


def _percentile_snapshot(samples: list) -> dict:
    n = len(samples)

    def _pct(p):
        if not samples:
            return 0.0
        idx = min(n - 1, max(0, round(p / 100.0 * (n - 1))))
        return round(samples[idx], 1)

    return {"p50": _pct(50), "p95": _pct(95), "p99": _pct(99), "n": n}


def record_detection_latency(ms: float, origin: str | None = None) -> None:
    with _latency_lock:
        _latency_samples_ms.append(ms)
        if origin in _latency_by_origin:
            _latency_by_origin[origin].append(ms)


def latency_percentiles() -> dict:
    with _latency_lock:
        samples = sorted(_latency_samples_ms)
    return _percentile_snapshot(samples)


def latency_percentiles_by_origin() -> dict:
    with _latency_lock:
        return {origin: _percentile_snapshot(sorted(buf))
                for origin, buf in _latency_by_origin.items()}

_sse_lock   = threading.Lock()
_sse_buffer: collections.deque = collections.deque(maxlen=500)

_sse_dedup: dict = {}
_SSE_DEDUP_TTL = 5.0

# -- Pending restores - IPs awaiting baseline traffic restart after manual release
_restore_lock     = threading.Lock()
_pending_restores: set[str] = set()

# -- Scan log - rolling buffer of last 200 flow evaluations for /api/debug/flows
_scan_lock   = threading.Lock()
_scan_buffer: collections.deque = collections.deque(maxlen=200)


# Called by worker for every flow that runs through IF inference.
def push_scan_result(src_ip: str, pps: float, sw_delta: float,
                     if_score: float, threshold: float, is_anomaly: bool,
                     attack_class: str, confidence: float) -> None:
    import datetime
    entry = {
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(pps, 1),
        "sw_delta":    round(sw_delta, 1),
        "if_score":    round(if_score, 4),
        "threshold":   round(threshold, 4),
        "is_anomaly":  is_anomaly,
        "attack_class": attack_class if is_anomaly else "Normal",
        "confidence":  f"{confidence*100:.1f}%" if is_anomaly else "-",
    }
    with _scan_lock:
        _scan_buffer.appendleft(entry)


def get_scan_log() -> list[dict]:
    with _scan_lock:
        return list(_scan_buffer)

# -- Pipeline debug log - rolling buffer of last 200 inference results
# Each entry: {src_ip, pps, if_score, threshold, is_anomaly,
#              attack_class, confidence, action, ts}
# Exposed via GET /api/debug so operators can see what the ML pipeline is doing.
_debug_lock   = threading.Lock()
_debug_buffer: collections.deque = collections.deque(maxlen=200)


def get_debug_log() -> list[dict]:
    with _debug_lock:
        return list(reversed(_debug_buffer))   # newest first


def _push_debug(entry: dict) -> None:
    with _debug_lock:
        _debug_buffer.append(entry)


# Accumulates real OVS dropped packet counts from ryu_controller.
def record_dropped_packets(src_ip: str, delta: int) -> None:
    with _lock:
        _stats["actual_pkts_dropped"] += delta


def get_stats() -> dict:
    with _lock:
        s = _stats.copy()
    samples = max(s["latency_samples"], 1)

    # real_dropped -- OVS physical drops preferred; fall back to ML-event count
    real_dropped = s["actual_pkts_dropped"] if s["actual_pkts_dropped"] > 0 else s["malicious_dropped"]

    # normal -- dedicated forwarded counter, incremented per normal flow result
    normal = s["normal_forwarded"]

    # total = malicious + normal only; raw OVS counts are excluded since they
    # recount the same packets every poll and include unclassified control traffic.
    total = real_dropped + normal

    return {
        "total_packets":     total,
        "malicious_dropped": real_dropped,
        "normal_packets":    normal,
        "active_threats":    len(state_machine.get_active_list()) + len(deception.get_active_list()),
        "fp_rate":           round((s["false_positives"] / max(s["ml_processed"], 1)) * 100, 2),
        "avg_latency_ms":    round(s["total_latency_ms"] / samples, 1),
    }


# -- False-positive handling ----------------------------------------------------

# Manual release of a blocked host (FP); buffers to traffic_summary and queues for restore.
def record_false_positive(src_ip: str) -> None:
    with _lock:
        _stats["false_positives"] += 1
    writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
    with _restore_lock:
        _pending_restores.add(src_ip)
    log.info("FP recorded for %s (manual release). fp_total=%d",
             src_ip, _stats["false_positives"])


# Drain and return IPs queued for baseline traffic restoration.
def drain_pending_restores() -> list[str]:
    with _restore_lock:
        ips = list(_pending_restores)
        _pending_restores.clear()
    return ips


# Reset per-IP confidence lock so stale campaign classifications do not persist.
def clear_confidence_lock() -> None:
    with _conf_lock_mutex:
        _conf_lock.clear()
    log.info("Confidence lock cleared")


def drain_sse_events() -> list[dict]:
    with _sse_lock:
        events = list(_sse_buffer)
        _sse_buffer.clear()
    return events


def _push_sse_event(event: dict, force: bool = False) -> None:
    now = time.monotonic()
    key = event.get("src_ip")
    with _sse_lock:
        last = _sse_dedup.get(key, 0)
        if not force and now - last < _SSE_DEDUP_TTL:
            return
        _sse_dedup[key] = now
        _sse_buffer.append(event)
        expired = [k for k, t in _sse_dedup.items() if now - t > _SSE_DEDUP_TTL * 10]
        for k in expired:
            del _sse_dedup[k]


def _assign_priority(if_score: float, confidence: float,
                     src_ip: str = "", attack_class: str = "Uncertain",
                     recent_pps: float = 0.0) -> str:
    from backend.mitigation.behavioral import assign_priority
    return assign_priority(
        if_score=if_score,
        confidence=confidence,
        src_ip=src_ip,
        attack_class=attack_class,
        recent_pps=recent_pps,
    )


# -- Detection ledger gate: one 'detected' row per phase entry ------------
# Keyed on IpState.phase_entered (monotonic); repeats within one entry are
# suppressed, and stale entries are pruned to bound memory under IP churn.
_DETECTION_LOGGED_MAX = 128
_detection_logged: dict[str, float] = {}


def _should_log_detection(src_ip: str, phase_entered: float | None) -> bool:
    if phase_entered is None:
        return True
    with _lock:
        if _detection_logged.get(src_ip) == phase_entered:
            return False
        _detection_logged[src_ip] = phase_entered
        if len(_detection_logged) > _DETECTION_LOGGED_MAX:
            live_states = state_machine.get_state_ips()
            for ip in [k for k in _detection_logged if k not in live_states]:
                del _detection_logged[ip]
        return True


def on_result(src_ip: str, if_score, is_anomaly,
              attack_class, confidence, *,
              flow_stats: dict = None, switch_stats: dict = None,
              timed_out: bool, enqueued_at: float = None,
              origin: str = None) -> None:
    from backend.api.stats import get_active_attacks as _get_gt
    t_start = time.monotonic()

    # Detection Time - flow queued (worker.submit) -> IF/RF result ready here.
    # None when not provided (e.g. timeout fallback path) - left as None in DB.
    detection_ms = ((t_start - enqueued_at) * 1000.0) if enqueued_at is not None else None
    if detection_ms is not None:
        record_detection_latency(detection_ms, origin=origin)

    with _lock:
        _stats["total_packets"] += 1

    # ML OFF - count packet as normal, skip all detection and mitigation.
    if not ML_ENABLED:
        _pkt_count = _estimate_pkt_count(flow_stats)
        _pps       = float((flow_stats or {}).get("packet_count_per_second", 0.0))
        _is_attack = src_ip in _ATTACKER_IPS

        with _lock:
            _stats["normal_packets"]   += 1
            _stats["normal_forwarded"] += _pkt_count

        # Write to traffic_summary so graph history shows traffic.
        # Attack IPs counted as incoming threats (visible on graph, no action).
        writer.log_traffic_summary(
            total=1,
            threats=(1 if _is_attack else 0),
            true_neg=(0 if _is_attack else 1),
            fp=0,
        )
        return

    if timed_out:
        state_machine.hold_ip(src_ip, reason="queue_timeout", ttl_s=15.0)
        with _lock:
            _stats["malicious_dropped"] += 1
        log.warning("Holding: %s (retries exhausted, unscored)", src_ip)
        return

    writer.log_detection_features(
        src_ip=src_ip,
        if_score=if_score or 0.0,
        is_anomaly=bool(is_anomaly),
        attack_class=attack_class or "Normal",
        confidence=confidence or 0.0,
        flow_stats=flow_stats or {},
        switch_stats=switch_stats or {},
    )

    with _lock:
        _stats["ml_processed"] += 1

    # -- Debug log: record every inference result ------------------------------
    _pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))

    # update sinkhole PPS so observation window can escalate/release correctly
    deception.update_pps(src_ip, _pps)
    # feed live score/confidence too, so the sinkhole tracks the latest
    # confidence instead of stale entry-time values
    deception.update_score(src_ip, if_score or 0.0, confidence or 0.0)

    _push_debug({
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(_pps, 2),
        "if_score":    round(if_score or 0.0, 4),
        "threshold":   round(loader.if_threshold, 4) if loader._loaded else 0,
        "is_anomaly":  bool(is_anomaly),
        "attack_class": attack_class or "Normal",
        "confidence":  round((confidence or 0.0) * 100, 1),
        "action":      "pending",
    })
    # Always refresh a tracked IP's live telemetry, even if it falls below the
    # anomaly threshold. This keeps recent_pps current for phase evaluation.
    state_machine.update_observation(
        src_ip, if_score, attack_class or "Normal", confidence or 0.0,
        float((flow_stats or {}).get("packet_count_per_second", 0.0)),
    )

    if not is_anomaly:
        _pkt_count = _estimate_pkt_count(flow_stats)
        with _lock:
            _stats["normal_packets"]  += 1
            _stats["normal_forwarded"] += _pkt_count

        # IF: normal -> TN if legit, FN if attacker (only if actively attacking)
        _is_attacker = src_ip in _get_gt()
        writer.log_traffic_summary(
            total=1, threats=0, true_neg=1, fp=0,
            tn=(0 if _is_attacker else 1),
            fn=(1 if _is_attacker else 0),
            if_tn=(0 if _is_attacker else 1),
            if_fn=(1 if _is_attacker else 0),
        )
        return

    loader.require_loaded()

    log.debug("Anomaly confirmed: %s  IF=%.4f  RF=%s  conf=%.1f%%",
              src_ip, if_score, attack_class, (confidence or 0)*100)

    # Check legit host before mitigation so FP counter updates immediately.
    is_known_legit = src_ip in _LEGIT_HOST_IPS
    if is_known_legit:
        with _lock:
            _stats["false_positives"] += 1
        writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
        log.warning("FALSE POSITIVE detected: %s is a known legit host!", src_ip)

    with _conf_lock_mutex:
        prev = _conf_lock.get(src_ip)
        if prev is not None:
            merged = _merge_confidence(prev, (confidence, attack_class))
            confidence, attack_class = merged
            _conf_lock[src_ip] = (confidence, attack_class)
        else:
            _conf_lock[src_ip] = (confidence, attack_class)

    predicted_class = "DDoS" if attack_class != "Uncertain" else "Anomaly"
    _recent_pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))
    priority        = _assign_priority(if_score, confidence, src_ip, attack_class, _recent_pps)

    # TEA mitigation gate. Every interval already went through IF/RF.
    # Ground truth counting below always runs, regardless of this decision.
    _tea_result = _build_tea_result(flow_stats)

    # TEA confidence-based routing
    _tea_confidence = _tea_result.get("confidence", "low")
    _tea_attack = _tea_result.get("is_attack_pattern", False)

    # High confidence attack -> ensure High priority (fast-track)
    if _tea_attack and _tea_confidence == "high" and if_score >= loader.if_threshold:
        if priority in ("Low", "Medium"):
            priority = "High"
            log.info("TEA high-confidence fast-track: %s -> High priority", src_ip)

    _already_flagged = flood_filter.is_flagged_any(src_ip)
    _tea_mitigate     = entropy_analyzer.should_submit(_tea_result, _already_flagged)
    mitigation_ms = None
    action_taken  = "Logged (flash crowd, no mitigation)"

    if _tea_mitigate:
        # Tell resource_guard the attack proto for CRIT tier drop rules.
        from backend.mitigation.resource_guard import resource_guard
        resource_guard.set_attack_proto(attack_class)

        # recent_pps is already refreshed for every result by
        # state_machine.update_observation() above - no direct mutation here.

        # Mitigation response time, result ready to FlowMod dispatched.
        t_mitigate_start = time.monotonic()

        existing = state_machine.get_state(src_ip)
        if existing is None:
            from backend.database.db import query as _q
            prior = _q(
                "SELECT ban_level, offence_count FROM ip_attack_history WHERE src_ip=? ORDER BY id DESC LIMIT 1",
                (src_ip,)
            )
            if prior and prior[0].get("ban_level", 0) is not None:
                prev_ban   = int(prior[0].get("ban_level", 0) or 0)
                prev_occ   = int(prior[0].get("offence_count", 0) or 0)
                if prev_ban > 0:
                    state_machine.on_reoffence(src_ip, if_score, attack_class, confidence, prev_ban, prev_occ,
                                               recent_pps=_recent_pps)
                    _post_state = state_machine.get_state(src_ip)
                    action_taken = _post_state.action_taken if _post_state else "Quarantined"
                else:
                    action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence,
                                                              recent_pps=_recent_pps)
            else:
                action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence,
                                                          recent_pps=_recent_pps)
        else:
            action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence,
                                                      recent_pps=_recent_pps)

        mitigation_ms = (time.monotonic() - t_mitigate_start) * 1000.0

        _pkt_count = int((flow_stats or {}).get("packet_count", 0)) or _estimate_pkt_count(flow_stats)
        with _lock:
            _stats["malicious_dropped"] += _pkt_count
    else:
        log.debug("TEA mitigation gate: flash crowd, logging only - %s", src_ip)

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_state    = state_machine.get_state(src_ip)
    phase_label = ip_state.phase_label() if ip_state else None

    # Skip the write for legit hosts and flash-crowd (no action taken).
    # The gate allows one 'detected' row per phase entry (writer dedup is a safety net).
    if not is_known_legit and _tea_mitigate and (
        ip_state is None or _should_log_detection(src_ip, ip_state.phase_entered)
    ):
        writer.log_mitigation_event(_build_mitigation_event(
            src_ip=src_ip,
            attack_vector=attack_class,
            confidence=confidence,
            priority=priority,
            action_taken=action_taken,
            if_score=if_score,
            phase=phase_label,
            event_type="detected",
            reason=None,
            session_id=ip_state.session_id if ip_state else None,
            is_manual=False,
            detection_ms=detection_ms,
            mitigation_ms=mitigation_ms,
        ))

    _threat_pps = _estimate_pkt_count(flow_stats)
    _is_tp      = src_ip in _get_gt()
    _is_legit   = src_ip in _LEGIT_HOST_IPS

    # IF metrics
    _if_tp = 1 if _is_tp    else 0
    _if_fp = 1 if _is_legit else 0

    # RF ground truth - use live topology-reported attack type
    from backend.api.stats import get_active_attacks as _get_gt
    _gt = _get_gt()
    _expected_class = _gt.get(src_ip)  # "SYN", "ICMP", "UDP" or None
    # MIXED is a topology-only label RF's 3-class model does not predict;
    # scoring it as FN/FP would corrupt the confusion matrix, so it is excluded.
    if _expected_class == "MIXED":
        _expected_class = None

    # Map RF attack_class to short type
    _class_map = {"SYN Flood": "SYN", "ICMP Flood": "ICMP", "UDP Flood": "UDP"}
    _predicted = _class_map.get(attack_class)
    _rf = _compute_rf_confusion(_expected_class, attack_class)

    writer.log_traffic_summary(
        total=1, threats=1, true_neg=0, fp=0,
        tp=(1 if _is_tp else 0),
        if_tp=_if_tp, if_fp=_if_fp,
        rf_tp=_rf["rf_tp"], rf_fp=_rf["rf_fp"], rf_tn=_rf["rf_tn"], rf_fn=_rf["rf_fn"],
        rf_tp_syn=_rf["rf_tp_syn"], rf_fp_syn=_rf["rf_fp_syn"],
        rf_tn_syn=_rf["rf_tn_syn"], rf_fn_syn=_rf["rf_fn_syn"],
        rf_tp_icmp=_rf["rf_tp_icmp"], rf_fp_icmp=_rf["rf_fp_icmp"],
        rf_tn_icmp=_rf["rf_tn_icmp"], rf_fn_icmp=_rf["rf_fn_icmp"],
        rf_tp_udp=_rf["rf_tp_udp"], rf_fp_udp=_rf["rf_fp_udp"],
        rf_tn_udp=_rf["rf_tn_udp"], rf_fn_udp=_rf["rf_fn_udp"],
        rf_syn_as_icmp=_rf["rf_syn_as_icmp"], rf_syn_as_udp=_rf["rf_syn_as_udp"],
        rf_icmp_as_syn=_rf["rf_icmp_as_syn"], rf_icmp_as_udp=_rf["rf_icmp_as_udp"],
        rf_udp_as_syn=_rf["rf_udp_as_syn"],   rf_udp_as_icmp=_rf["rf_udp_as_icmp"],
    )

    elapsed_ms = (time.monotonic() - t_start) * 1000
    with _lock:
        _stats["total_latency_ms"] += elapsed_ms
        _stats["latency_samples"]  += 1

    # Update debug log entry with confirmed action
    _push_debug({
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(_pps, 2),
        "if_score":    round(if_score or 0.0, 4),
        "threshold":   round(loader.if_threshold, 4) if loader._loaded else 0,
        "is_anomaly":  True,
        "attack_class": attack_class,
        "confidence":  round((confidence or 0.0) * 100, 1),
        "action":      action_taken,
    })

    # Push SSE for every detection so the audit log reflects live activity.
    # All detections bypass dedup to ensure the audit log is never stale.
    if not is_known_legit and _tea_mitigate:
        _push_sse_event(_build_sse_event(
            src_ip=src_ip,
            attack_vector=attack_class,
            confidence=confidence,
            priority=priority,
            action_taken=action_taken,
            event_type="released" if action_taken == "Released" else "transition",
            session_id=ip_state.session_id if ip_state else None,
        ), force=True)


def start() -> None:
    worker.set_result_callback(on_result)
    worker.start()
    log.info("Decision engine ready")