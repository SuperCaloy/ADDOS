from flask import Blueprint, jsonify, request
from backend.pipeline.decision_engine import get_stats, get_scan_log, clear_confidence_lock
from backend.pipeline.flow_tracker import tracker
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader
from backend.database.db import query, execute
import threading
import time
import logging

log = logging.getLogger(__name__)

bp = Blueprint("stats", __name__)

# Ground truth store — populated by topology when attacks start/stop.
# Persisted to DB so it survives backend restarts (fixes RF metrics going to 0
# when the topology sent notifications before the backend was listening).
_gt_lock:  threading.Lock = threading.Lock()
_active_attacks: dict[str, tuple[str, float]] = {}
_gt_loaded = False  # one-shot flag: load from DB on first access

GT_TTL_S = 3600  # stale-after-crash backstop; must exceed the LONGEST
# legitimate continuous session (mixed campaigns run 30-45+ min), so a
# mid-demo purge can never crater accuracy accounting while traffic flows


def _load_gt_from_db() -> None:
    """Load active (non-stopped) ground truth entries from DB into memory."""
    global _gt_loaded
    try:
        rows = query(
            "SELECT src_ip, attack_type, started_at FROM ground_truth "
            "WHERE stopped_at IS NULL"
        )
        now = time.time()
        loaded = 0
        for r in rows:
            ip      = r["src_ip"]
            atype   = r["attack_type"]
            started = float(r["started_at"])
            # Skip expired entries (TTL check)
            if now - started > GT_TTL_S:
                continue
            _active_attacks[ip] = (atype, started)
            loaded += 1
        if loaded:
            log.info("Ground truth loaded from DB: %d active entries", loaded)
    except Exception:
        log.exception("Failed to load ground truth from DB")
    finally:
        _gt_loaded = True


def get_active_attacks() -> dict[str, str]:
    now = time.time()
    with _gt_lock:
        if not _gt_loaded:
            _load_gt_from_db()
        expired = [ip for ip, (_, started) in _active_attacks.items()
                   if now - started > GT_TTL_S]
        for ip in expired:
            del _active_attacks[ip]
        return {ip: atype for ip, (atype, _) in _active_attacks.items()}


@bp.get("/api/stats")
def stats():
    # Read from in-memory counters for real-time display (no 5s DB flush lag)
    try:
        mem_stats = get_stats()
        total     = mem_stats.get("total_packets", 0)
        malicious = mem_stats.get("malicious_dropped", 0)
        normal    = mem_stats.get("normal_packets", 0)
        active    = mem_stats.get("active_threats", 0)
    except Exception:
        total, malicious, normal, active = 0, 0, 0, 0

    # Historical latency from mitigation_events (all-time, like other cards)
    try:
        lat_rows = query("""
            SELECT AVG(detection_ms) as avg_detect, AVG(mitigation_ms) as avg_mitigate
            FROM mitigation_events
            WHERE detection_ms IS NOT NULL OR mitigation_ms IS NOT NULL
        """)
        lr = lat_rows[0] if lat_rows else {}
        hist_detect_ms  = round(float(lr.get("avg_detect")   or 0), 2)
        hist_mitig_ms   = round(float(lr.get("avg_mitigate") or 0), 2)
    except Exception:
        hist_detect_ms, hist_mitig_ms = 0, 0

    # FP rate from DB — same formula as report (if_fp / (if_fp + if_tn))
    try:
        fp_rows = query("""
            SELECT SUM(if_fp) as fp, SUM(if_tn) as tn
            FROM traffic_summary
        """)
        fpr = 0.0
        if fp_rows and fp_rows[0]:
            _fp = float(fp_rows[0].get("fp") or 0)
            _tn = float(fp_rows[0].get("tn") or 0)
            fpr = round((_fp / max(_fp + _tn, 1)) * 100, 2)
    except Exception:
        fpr = 0.0

    return jsonify({
        # Summary cards (in-memory, real-time)
        "total_packets":     total,
        "malicious_dropped": malicious,
        "normal_packets":    normal,

        # Live chart — same values, cards and chart always match
        "live_total":        total,
        "live_malicious":    malicious,
        "live_normal":       normal,

        # Session metrics
        "active_threats":    active,
        "avg_latency_ms":    hist_detect_ms,
        "fp_rate":           fpr,

        # Historical latency (all-time from DB, persistent across sessions)
        "detection_ms":      hist_detect_ms,
        "mitigation_ms":     hist_mitig_ms,
    })


def _compute_accuracy():
    try:
        # IF: real accuracy from ground truth tp/fp/tn/fn, all time
        if_rows = query("""
            SELECT SUM(if_tp) as tp, SUM(if_fp) as fp,
                   SUM(if_tn) as tn, SUM(if_fn) as fn
            FROM traffic_summary
        """)
        r = if_rows[0] if if_rows else {}
        tp, fp = float(r.get("tp") or 0), float(r.get("fp") or 0)
        tn, fn = float(r.get("tn") or 0), float(r.get("fn") or 0)
        if_total = tp + fp + tn + fn
        if_acc = round((tp + tn) / if_total * 100, 1) if if_total else None

        # RF: real accuracy from 3x3 confusion matrix, all time
        rf_rows = query("""
            SELECT SUM(rf_tp_syn)  as tp_syn,  SUM(rf_tp_icmp) as tp_icmp,
                   SUM(rf_tp_udp)  as tp_udp,
                   SUM(rf_syn_as_icmp) as syn_as_icmp, SUM(rf_syn_as_udp)  as syn_as_udp,
                   SUM(rf_icmp_as_syn) as icmp_as_syn, SUM(rf_icmp_as_udp) as icmp_as_udp,
                   SUM(rf_udp_as_syn)  as udp_as_syn,  SUM(rf_udp_as_icmp) as udp_as_icmp
            FROM traffic_summary
        """)
        rr = rf_rows[0] if rf_rows else {}
        g  = lambda k: float(rr.get(k) or 0)
        correct = g("tp_syn") + g("tp_icmp") + g("tp_udp")
        wrong   = (g("syn_as_icmp") + g("syn_as_udp") + g("icmp_as_syn") +
                   g("icmp_as_udp") + g("udp_as_syn") + g("udp_as_icmp"))
        rf_total = correct + wrong
        rf_acc = round(correct / rf_total * 100, 1) if rf_total else None

        return if_acc, rf_acc
    except Exception:
        return None, None


@bp.get("/api/model_info")
def model_info():
    loader.require_loaded()
    if_acc, rf_acc = _compute_accuracy()
    return jsonify({
        "if_accuracy":  if_acc,
        "rf_accuracy":  rf_acc,
        "if_threshold": loader.if_threshold,
        "rf_conf_gate": loader.rf_conf_gate,
        "if_features":  loader.if_features,
        "rf_features":  loader.rf_features,
        "rf_classes":   loader.rf_classes,
    })


@bp.get("/api/db_path")
def db_path():
    # Lets the benchmark confirm the backend booted onto the benchmark DB
    # before the timeline starts.
    from backend.config import DB_PATH as _DB_PATH
    return jsonify({"db_path": _DB_PATH})


@bp.get("/api/system_metrics")
def system_metrics():
    rows = query("""
        SELECT cpu_percent, mem_mb, ctrl_cpu_percent, ctrl_mem_mb
        FROM system_metrics ORDER BY id DESC LIMIT 1
    """)
    if not rows:
        return jsonify({"cpu": 0, "mem_mb": 0, "ctrl_cpu": 0, "ctrl_mem": 0})
    r = rows[0]
    return jsonify({
        "cpu":      round(r["cpu_percent"] or 0, 2),
        "mem_mb":   round(r["mem_mb"] or 0, 2),
        "ctrl_cpu": round(r["ctrl_cpu_percent"] or 0, 2),
        "ctrl_mem": round(r["ctrl_mem_mb"] or 0, 2),
    })


@bp.get("/api/debug/flows")
def debug_flows():
    return jsonify(get_scan_log())


@bp.post("/api/attack_ground_truth/start")
def gt_start():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip")
    atype = body.get("attack_type")  # "SYN", "ICMP", "UDP"
    if not ip or not atype:
        return jsonify({"error": "ip and attack_type required"}), 400
    now = time.time()
    with _gt_lock:
        _active_attacks[ip] = (atype, now)
    # Persist to DB so ground truth survives backend restarts
    try:
        execute(
            "INSERT INTO ground_truth (src_ip, attack_type, started_at) VALUES (?, ?, ?)",
            (ip, atype, now),
        )
    except Exception:
        log.exception("Failed to persist ground truth start for %s", ip)
    return jsonify({"ok": True})


@bp.post("/api/attack_ground_truth/stop")
def gt_stop():
    body   = request.get_json(silent=True) or {}
    ip     = body.get("ip")
    cutoff = body.get("cutoff")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    with _gt_lock:
        entry = _active_attacks.get(ip)
        if entry is None:
            return jsonify({"ok": True})
        # Race guard (Round 5 S8): a stranded stop from an OLD campaign
        # must never delete a NEWER campaign's entry for the same IP.
        if isinstance(cutoff, (int, float)) and entry[1] > cutoff:
            return jsonify({"ok": True, "ignored": "newer campaign"})
        del _active_attacks[ip]
    # Mark as stopped in DB
    try:
        now = time.time()
        execute(
            "UPDATE ground_truth SET stopped_at = ? "
            "WHERE src_ip = ? AND stopped_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (now, ip),
        )
    except Exception:
        log.exception("Failed to persist ground truth stop for %s", ip)
    return jsonify({"ok": True})


@bp.post("/api/attack_ground_truth/stop_all")
def gt_stop_all():
    # S6/Round 5: one batched stop for the whole attack family. The cutoff
    # makes it race-safe: entries started AFTER the caller captured its
    # cutoff belong to a NEWER campaign and must survive this stop.
    body   = request.get_json(silent=True) or {}
    cutoff = body.get("cutoff")
    with _gt_lock:
        if isinstance(cutoff, (int, float)) and cutoff > 0:
            victims = [ip for ip, (_, started) in _active_attacks.items()
                       if started <= cutoff]
        else:
            victims = list(_active_attacks.keys())
        for ip in victims:
            del _active_attacks[ip]
    # Mark all stopped entries in DB
    try:
        now = time.time()
        if isinstance(cutoff, (int, float)) and cutoff > 0:
            execute(
                "UPDATE ground_truth SET stopped_at = ? "
                "WHERE stopped_at IS NULL AND started_at <= ?",
                (now, cutoff),
            )
        else:
            execute(
                "UPDATE ground_truth SET stopped_at = ? WHERE stopped_at IS NULL",
                (now,),
            )
    except Exception:
        log.exception("Failed to persist ground truth stop_all")
    # Clear the confidence lock so stale high-confidence classifications
    # from the previous campaign cannot ratchet over fresh RF results.
    clear_confidence_lock()
    return jsonify({"ok": True, "cleared": len(victims)})


@bp.get("/api/attack_ground_truth")
def gt_list():
    return jsonify(get_active_attacks())
