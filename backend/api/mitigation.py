# REST API endpoints for quarantine inspection and manual mitigation actions.
# Allows operators to inspect active quarantined hosts, release false positives, and clear state.

import logging
from flask import Blueprint, jsonify, request
from backend.mitigation.state_machine import state_machine
from backend.mitigation.deception import deception
from backend.pipeline.decision_engine import record_false_positive, drain_pending_restores
from backend.pipeline.flow_tracker import tracker

log = logging.getLogger(__name__)
bp = Blueprint("quarantine", __name__)


@bp.get("/api/quarantine_list")
def quarantine_list():
    # Returns combined list of currently quarantined and sinkholed IP addresses.
    # Combines state machine active mitigations and deceptive honeypot redirections.
    rows = state_machine.get_active_list()
    seen = {r["src_ip"] for r in rows}
    for e in deception.get_active_list():
        if e["src_ip"] in seen:
            # One IP, one home: the state machine copy wins so the list
            # matches the drawer, which also reads the state machine first.
            continue
        rows.append({
            "src_ip":            e["src_ip"],
            "phase":             e["phase"],
            "phase_label":       e["phase_label"],
            "attack_vector":     e["attack_vector"],
            "if_score":          e["if_score"],
            "confidence":        e["confidence"],
            "time_in_phase_sec": e.get("elapsed_sec", 0),
            "ttl_remaining_sec": e.get("remaining_sec", 0),
            "recent_pps":        e.get("recent_pps", 0.0),
            "priority":          "Low",
        })
    return jsonify(rows)


@bp.post("/api/quarantine/release")
def release():
    # Releases an IP address from active quarantine and records a false positive count.
    src_ip = (request.get_json(silent=True) or {}).get("src_ip", "").strip()
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400

    # --- Try state machine first ---
    released = state_machine.manual_release(src_ip)

    # --- If not in state machine, check sinkhole ---
    if not released and deception.is_sinkholes(src_ip):
        deception.emergency_clear_one(src_ip)
        released = True

    if not released:
        return jsonify({"error": f"{src_ip} not found in active list"}), 404

    record_false_positive(src_ip)
    return jsonify({"status": "released", "src_ip": src_ip})


@bp.post("/api/quarantine/block")
def block():
    # Manually escalates an IP address to permanent blocking.
    src_ip = (request.get_json(silent=True) or {}).get("src_ip", "").strip()
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400

    state_machine.manual_block(src_ip)
    return jsonify({"status": "blocked", "src_ip": src_ip})


@bp.post("/api/quarantine/clear_all")
def clear_all():
    # Clears all active non-permanent mitigations from state machine and sinkhole redirects.
    cleared = state_machine.clear_all_non_permanent()
    cleared += deception.emergency_clear()
    return jsonify({"status": "ok", "cleared": cleared})


@bp.get("/api/pending_restores")
def pending_restores():
    # Returns list of IP addresses scheduled for rule restoration on controller switches.
    ips = drain_pending_restores()
    return jsonify({"ips": ips})


@bp.post("/api/cache/invalidate")
def invalidate_cache():
    # Flushes cached flow tracker predictions for a specific source IP.
    src_ip = (request.get_json(silent=True) or {}).get("src_ip", "").strip()
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400

    tracker.invalidate_cache(src_ip)
    return jsonify({"ok": True, "src_ip": src_ip})


# Local admin endpoint for benchmark live reset, no auth layer in this backend.
@bp.post("/api/admin/reset_reputation")
def reset_reputation():
    # Resets in-memory reputation scores, offense ledger caches, and state machine records.
    from backend.database.writer import clear_reputation_cache

    clear_reputation_cache()
    state_machine.clear_states()
    return jsonify({"ok": True})