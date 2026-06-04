from flask import Blueprint, jsonify
from backend.pipeline.decision_engine import get_stats, get_scan_log
from backend.pipeline.flow_tracker import tracker
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader
from backend.database.db import query

bp = Blueprint("stats", __name__)


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


@bp.get("/api/model_info")
def model_info():
    loader.require_loaded()
    return jsonify({
        "if_accuracy":  None,
        "rf_accuracy":  None,
        "if_threshold": loader.if_threshold,
        "rf_conf_gate": loader.rf_conf_gate,
        "if_features":  loader.if_features,
        "rf_features":  loader.rf_features,
        "rf_classes":   loader.rf_classes,
    })


@bp.get("/api/debug/flows")
def debug_flows():
    return jsonify(get_scan_log())