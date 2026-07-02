import time
import logging
import threading
import datetime
import collections
from backend.mitigation.state_machine import state_machine
from backend.mitigation.deception import deception
from backend.database import writer
from backend.pipeline import worker
from backend.models import loader
from backend.config import ML_ENABLED

log = logging.getLogger(__name__)


def _estimate_pkt_count(flow_stats: dict) -> int:
    """Real packet_count from the OVS flow-stats poll, when present.

    Falls back to packet_count_per_second (this worker cycle is ~1s, so
    pps approximates the packet count for that window) when flow_stats
    is missing or stale — e.g. during a switch reconnect. Previously
    this fell back to a hardcoded 1, which massively undercounts real
    traffic during a flood.
    """
    fs  = flow_stats or {}
    raw = fs.get("packet_count")
    if raw is not None:
        return max(int(raw), 1)
    pps = float(fs.get("packet_count_per_second", 0.0))
    return max(int(round(pps)), 1)


_lock = threading.Lock()

# Confidence lock — keeps highest seen confidence+attack_class per IP
# Only updates if new confidence > locked value
_conf_lock: dict[str, tuple[float, str]] = {}
_conf_lock_mutex = threading.Lock()

_LEGIT_HOST_IPS: frozenset = frozenset([
    "10.0.0.1",  # h1
    "10.0.0.2",  # h2
    "10.0.0.3",  # h3
    "10.0.0.4",  # h4
    "10.0.0.5", # h5
])

# Ground truth — attacker hosts h6-h19
_ATTACKER_IPS: frozenset = frozenset([f"10.0.0.{i}" for i in range(6, 20)])

_stats = {
    "total_packets":       0,
    "malicious_dropped":   0,   # ML events classified as malicious
    "actual_pkts_dropped": 0,   # real OVS physical drops from dropped_delta messages
    "normal_packets":      0,
    # Dedicated legit counter — incremented directly when IF says normal.
    # Avoids subtraction (raw_total - dropped) which breaks when attackers dominate.
    "normal_forwarded":    0,
    "false_positives":     0,
    "ml_processed":        0,
    "total_latency_ms":    0.0,
    "latency_samples":     0,
}

_sse_lock   = threading.Lock()
_sse_buffer: collections.deque = collections.deque(maxlen=200)

_sse_dedup: dict = {}
_SSE_DEDUP_TTL = 5.0

# ── Pending restores — IPs awaiting baseline traffic restart after manual release
_restore_lock     = threading.Lock()
_pending_restores: set[str] = set()

# ── Scan log — rolling buffer of last 200 flow evaluations for /api/debug/flows
_scan_lock   = threading.Lock()
_scan_buffer: collections.deque = collections.deque(maxlen=200)


def push_scan_result(src_ip: str, pps: float, sw_delta: float,
                     if_score: float, threshold: float, is_anomaly: bool,
                     attack_class: str, confidence: float) -> None:
    """Called by worker for every flow that runs through IF inference."""
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
        "confidence":  f"{confidence*100:.1f}%" if is_anomaly else "—",
    }
    with _scan_lock:
        _scan_buffer.appendleft(entry)


def get_scan_log() -> list[dict]:
    with _scan_lock:
        return list(_scan_buffer)

# ── Pipeline debug log — rolling buffer of last 200 inference results
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


def record_dropped_packets(src_ip: str, delta: int) -> None:
    """Called by ZMQ receiver for every 'dropped_delta' message from ryu_controller.

    F3 fix: accumulates REAL physical packet drop counts from OVS blocked flow
    entries (priority 80/90/100). This gives the UI an accurate 'Malicious Dropped'
    counter instead of the misleading per-ML-event count.

    Call this from zmq_receiver.py when msg["type"] == "dropped_delta":
        from backend.pipeline.decision_engine import record_dropped_packets
        record_dropped_packets(msg["src_ip"], msg["delta"])
    """
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

    # total -- malicious + normal only (industry standard: total analyzed by ML pipeline)
    # Raw OVS packet counts are excluded -- they recount the same packets every poll
    # and include ARP/broadcast/control traffic never classified by the ML pipeline.
    # This ensures total always equals malicious + normal exactly.
    total = real_dropped + normal

    return {
        "total_packets":     total,
        "malicious_dropped": real_dropped,
        "normal_packets":    normal,
        "active_threats":    len(state_machine.get_active_list()) + len(deception.get_active_list()),
        "fp_rate":           round((s["false_positives"] / max(s["ml_processed"], 1)) * 100, 2),
        "avg_latency_ms":    round(s["total_latency_ms"] / samples, 1),
    }


# ── FP rate fix ────────────────────────────────────────────────────────────────

def record_false_positive(src_ip: str) -> None:
    """Called by quarantine.py on every manual release.

    Manual release = operator confirmed a blocked host was legitimate = real FP.

    H4 fix: also buffers fp=1 into traffic_summary so the PDF report's
    FP rate reflects operational ground truth.  The flush guard in writer.py
    was also fixed (it previously skipped total=0 entries, dropping FP rows).

    Also queues src_ip for auto-restoration of baseline traffic (Feature 2).
    """
    with _lock:
        _stats["false_positives"] += 1
    # H4: write to traffic_summary so report.py sees it (flushed within 5s)
    writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
    # Feature 2: queue for baseline restore polling
    with _restore_lock:
        _pending_restores.add(src_ip)
    log.info("FP recorded for %s (manual release). fp_total=%d",
             src_ip, _stats["false_positives"])


def drain_pending_restores() -> list[str]:
    """Drain and return IPs queued for baseline traffic restoration.

    Called by GET /api/pending_restores, polled by topology.py every 5s.
    """
    with _restore_lock:
        ips = list(_pending_restores)
        _pending_restores.clear()
    return ips


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


def _assign_priority(if_score: float, confidence: float) -> str:
    loader.require_loaded()
    if if_score >= loader.if_threshold * 1.2 and confidence >= 0.75:
        return "High"
    return "Low"


def on_result(src_ip: str, if_score, is_anomaly,
              attack_class, confidence, *,
              flow_stats: dict = None, switch_stats: dict = None,
              timed_out: bool, enqueued_at: float = None) -> None:
    t_start = time.monotonic()

    # Detection Time — flow queued (worker.submit) → IF/RF result ready here.
    # None when not provided (e.g. timeout fallback path) — left as None in DB.
    detection_ms = ((t_start - enqueued_at) * 1000.0) if enqueued_at is not None else None

    with _lock:
        _stats["total_packets"] += 1

    # --- ML OFF — count packet as normal, skip all detection and mitigation ---
    # ML OFF — show traffic visually but take NO action
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
            total=_pkt_count,
            threats=(_pkt_count if _is_attack else 0),
            true_neg=(0 if _is_attack else _pkt_count),
            fp=0,
        )
        return

    if timed_out:
        state_machine.manual_block(src_ip)
        with _lock:
            _stats["malicious_dropped"] += 1
        log.warning("Fallback block: %s (pipeline timeout)", src_ip)
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

    # ── Debug log — record every inference result ─────────────────────────────
    _pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))

    # update sinkhole PPS so observation window can escalate/release correctly
    deception.update_pps(src_ip, _pps)

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

    if not is_anomaly:
        _pkt_count = _estimate_pkt_count(flow_stats)
        with _lock:
            _stats["normal_packets"]  += 1
            _stats["normal_forwarded"] += _pkt_count

        # IF: normal → TN if legit, FN if attacker
        _is_attacker = src_ip in _ATTACKER_IPS
        writer.log_traffic_summary(
            total=_pkt_count, threats=0, true_neg=_pkt_count, fp=0,
            tn=(0 if _is_attacker else 1),
            fn=(1 if _is_attacker else 0),
            if_tn=(0 if _is_attacker else 1),
            if_fn=(1 if _is_attacker else 0),
        )
        return

    loader.require_loaded()

    log.debug("Anomaly confirmed: %s  IF=%.4f  RF=%s  conf=%.1f%%",
              src_ip, if_score, attack_class, (confidence or 0)*100)

    # Inform resource_guard of the current attack protocol.
    # Allows CRIT tier to install protocol-specific OVS drop rules
    # that catch rand-source floods bypassing per-IP block rules.
    from backend.mitigation.resource_guard import resource_guard
    resource_guard.set_attack_proto(attack_class)

    # F4 fix: update recent_pps on the state so _evaluate_phase1 can check
    # whether traffic is still active before escalating to a time ban.
    _recent_pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))
    with state_machine._lock:
        _existing_state = state_machine._states.get(src_ip)
        if _existing_state is not None:
            _existing_state.recent_pps = _recent_pps

    # Bug 3a fix: check if legit host BEFORE mitigation so FPR updates immediately
    # in the UI. Previously this check ran after on_detection() and db writes,
    # causing the FP counter to lag behind what was shown in the dashboard.
    is_known_legit = src_ip in _LEGIT_HOST_IPS
    if is_known_legit:
        with _lock:
            _stats["false_positives"] += 1
        writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
        log.warning("FALSE POSITIVE detected: %s is a known legit host!", src_ip)

    # Confidence lock — only update attack_class/confidence if new > locked
    with _conf_lock_mutex:
        prev = _conf_lock.get(src_ip)
        if prev is not None and confidence < prev[0]:
            confidence   = prev[0]
            attack_class = prev[1]
        else:
            _conf_lock[src_ip] = (confidence, attack_class)

    predicted_class = "DDoS" if attack_class != "Uncertain" else "Anomaly"
    priority        = _assign_priority(if_score, confidence)

    # Mitigation Response Time — IF/RF result ready (t_start) → FlowMod dispatched.
    # on_detection()/on_reoffence() are synchronous, so by the time they return
    # the command has already been pushed to the commander.
    t_mitigate_start = time.monotonic()

    # Check if IP was previously banned and is re-offending
    existing = state_machine._states.get(src_ip)
    if existing is None:
        # Check history for prior bans on this IP
        from backend.database.db import query as _q
        prior = _q(
            "SELECT ban_level, offence_count FROM ip_attack_history WHERE src_ip=? ORDER BY id DESC LIMIT 1",
            (src_ip,)
        )
        if prior and prior[0].get("ban_level", 0) is not None:
            prev_ban   = int(prior[0].get("ban_level", 0) or 0)
            prev_off   = int(prior[0].get("offence_count", 0) or 0)
            if prev_ban > 0:  # only re-offence if previously banned, not just quarantined
                state_machine.on_reoffence(src_ip, if_score, attack_class, confidence, prev_ban, prev_off)
                action_taken = state_machine._states[src_ip].action_taken if src_ip in state_machine._states else "Quarantined"
            else:
                action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)
        else:
            action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)
    else:
        action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)

    mitigation_ms = (time.monotonic() - t_mitigate_start) * 1000.0

    with _lock:
        _stats["malicious_dropped"] += 1

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_state    = state_machine._states.get(src_ip)
    phase_label = ip_state.phase_label() if ip_state else None

    # Skip DB mitigation write for known legit hosts.
    # FP is already counted above — writing a "DDoS" row here would
    # corrupt ground truth. Only real attackers get a mitigation record.
    if not is_known_legit:
        writer.log_mitigation_event({
        "timestamp":       ts,
        "src_ip":          src_ip,
        "predicted_class": predicted_class,
        "attack_vector":   attack_class,
        "confidence":      confidence,
        "priority":        priority,
        "action_taken":    action_taken,
        "if_score":        if_score,
        "phase":           phase_label,
        "is_manual":       0,
        "force_insert":    True,   # never overwrite existing rows
        "detection_ms":    detection_ms,
        "mitigation_ms":   mitigation_ms,
        })

    _threat_pps = _estimate_pkt_count(flow_stats)
    _is_tp      = src_ip in _ATTACKER_IPS
    _is_legit   = src_ip in _LEGIT_HOST_IPS

    # IF metrics
    _if_tp = 1 if _is_tp    else 0
    _if_fp = 1 if _is_legit else 0

    # RF ground truth — use live topology-reported attack type
    from backend.api.stats import get_active_attacks as _get_gt
    _gt = _get_gt()
    _expected_class = _gt.get(src_ip)  # "SYN", "ICMP", "UDP" or None

    # Map RF attack_class to short type
    _class_map = {"SYN Flood": "SYN", "ICMP Flood": "ICMP", "UDP Flood": "UDP"}
    _predicted  = _class_map.get(attack_class)

    _rf_tp = _rf_fp = _rf_tn = _rf_fn = 0
    _rf_tp_syn = _rf_fp_syn = _rf_tn_syn = _rf_fn_syn = 0
    _rf_tp_icmp= _rf_fp_icmp= _rf_tn_icmp= _rf_fn_icmp= 0
    _rf_tp_udp = _rf_fp_udp = _rf_tn_udp = _rf_fn_udp = 0
    _rf_syn_as_icmp = _rf_syn_as_udp = 0
    _rf_icmp_as_syn = _rf_icmp_as_udp = 0
    _rf_udp_as_syn  = _rf_udp_as_icmp = 0

    if _expected_class and _predicted:
        if _predicted == _expected_class:
            _rf_tp = 1
            if _expected_class == "SYN":
                _rf_tp_syn = 1; _rf_tn_icmp = 1; _rf_tn_udp = 1
            elif _expected_class == "ICMP":
                _rf_tp_icmp = 1; _rf_tn_syn = 1; _rf_tn_udp = 1
            elif _expected_class == "UDP":
                _rf_tp_udp = 1; _rf_tn_syn = 1; _rf_tn_icmp = 1
        else:
            # Misclassification — track off-diagonal cell
            _rf_fp = 1; _rf_fn = 1
            _mis = (_expected_class, _predicted)
            if   _mis == ("SYN",  "ICMP"): _rf_syn_as_icmp  = 1
            elif _mis == ("SYN",  "UDP"):  _rf_syn_as_udp   = 1
            elif _mis == ("ICMP", "SYN"):  _rf_icmp_as_syn  = 1
            elif _mis == ("ICMP", "UDP"):  _rf_icmp_as_udp  = 1
            elif _mis == ("UDP",  "SYN"):  _rf_udp_as_syn   = 1
            elif _mis == ("UDP",  "ICMP"): _rf_udp_as_icmp  = 1
    elif _expected_class and not _predicted:
        _rf_fn = 1
        if _expected_class == "SYN":   _rf_fn_syn  = 1
        elif _expected_class == "ICMP": _rf_fn_icmp = 1
        elif _expected_class == "UDP":  _rf_fn_udp  = 1

    writer.log_traffic_summary(
        total=_threat_pps, threats=_threat_pps, true_neg=0, fp=0,
        tp=(1 if _is_tp else 0),
        if_tp=_if_tp, if_fp=_if_fp,
        rf_tp=_rf_tp, rf_fp=_rf_fp, rf_tn=_rf_tn, rf_fn=_rf_fn,
        rf_tp_syn=_rf_tp_syn, rf_fp_syn=_rf_fp_syn,
        rf_tn_syn=_rf_tn_syn, rf_fn_syn=_rf_fn_syn,
        rf_tp_icmp=_rf_tp_icmp, rf_fp_icmp=_rf_fp_icmp,
        rf_tn_icmp=_rf_tn_icmp, rf_fn_icmp=_rf_fn_icmp,
        rf_tp_udp=_rf_tp_udp, rf_fp_udp=_rf_fp_udp,
        rf_tn_udp=_rf_tn_udp, rf_fn_udp=_rf_fn_udp,
        rf_syn_as_icmp=_rf_syn_as_icmp, rf_syn_as_udp=_rf_syn_as_udp,
        rf_icmp_as_syn=_rf_icmp_as_syn, rf_icmp_as_udp=_rf_icmp_as_udp,
        rf_udp_as_syn=_rf_udp_as_syn,   rf_udp_as_icmp=_rf_udp_as_icmp,
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

    # Force-push SSE on phase upgrades (Quarantine→TimeBan, →Blackhole)
    # so the audit log always reflects the latest phase, bypassing dedup.
    _phase_upgrade = action_taken in ("Time Ban", "Blackhole")
    _push_sse_event({
        "timestamp":       ts,
        "src_ip":          src_ip,
        "predicted_class": predicted_class,
        "attack_vector":   attack_class,
        "confidence":      f"{confidence * 100:.1f}%",
        "priority":        priority,
        "action_taken":    action_taken,
    }, force=_phase_upgrade)


def start() -> None:
    worker.set_result_callback(on_result)
    worker.start()
    log.info("Decision engine ready")