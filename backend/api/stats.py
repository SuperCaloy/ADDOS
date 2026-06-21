from flask import Blueprint, jsonify, request
from backend.pipeline.decision_engine import get_stats, get_scan_log
from backend.pipeline.flow_tracker import tracker
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader
from backend.database.db import query
import threading

bp = Blueprint("stats", __name__)

# Ground truth store — populated by topology when attacks start/stop
_gt_lock:  threading.Lock = threading.Lock()
_active_attacks: dict[str, str] = {}  # ip -> attack_type ("SYN"/"ICMP"/"UDP")


def get_active_attacks() -> dict[str, str]:
    with _gt_lock:
        return dict(_active_attacks)


@bp.get("/api/stats")
def stats():
    # decision_engine.get_stats() is the single source of truth
    # It applies: raw_total floor, OVS drop accounting, normal = total - dropped
    session = get_stats()

    total    = session["total_packets"]
    malicious = session["malicious_dropped"]
    normal   = session["normal_packets"]

    return jsonify({
        # Summary cards
        "total_packets":     total,
        "malicious_dropped": malicious,
        "normal_packets":    normal,

        # Live chart — same values, cards and chart always match
        "live_total":        total,
        "live_malicious":    malicious,
        "live_normal":       normal,

        # Session metrics
        "active_threats":    session.get("active_threats", 0),
        "avg_latency_ms":    session.get("avg_latency_ms", 0),
        "fp_rate":           session.get("fp_rate", 0.0),
    })


def _compute_accuracy():
    try:
        rows = query("""
            SELECT is_anomaly, attack_class, confidence
            FROM detection_features ORDER BY id DESC LIMIT 500
        """)
        if not rows:
            return None, None
        # IF: anomaly flag vs actual class
        if_correct = sum(1 for r in rows
                         if (r["is_anomaly"] == 1) == (r["attack_class"] != "Normal"))
        if_acc = round((if_correct / len(rows)) * 100, 1)
        # RF: avg confidence on confirmed attack rows
        atk = [r for r in rows if r["attack_class"] not in ("Normal", "Uncertain")]
        rf_acc = round(sum(r["confidence"] for r in atk) / len(atk) * 100, 1) if atk else None
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
    with _gt_lock:
        _active_attacks[ip] = atype
    return jsonify({"ok": True})


@bp.post("/api/attack_ground_truth/stop")
def gt_stop():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    with _gt_lock:
        _active_attacks.pop(ip, None)
    return jsonify({"ok": True})


@bp.get("/api/attack_ground_truth")
def gt_list():
    return jsonify(get_active_attacks())