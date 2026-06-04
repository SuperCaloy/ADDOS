"""
backend/api/ip_detail.py — Dedicated IP threat analysis endpoints.

Two endpoints:
  GET /api/ip_detail/<ip>       — full detail, live if active else DB fallback
  GET /api/ip_detail/<ip>/live  — real-time features only, 404 if not active

Separated from stats.py so polling logic is isolated and stats stays clean.
"""

from flask import Blueprint, jsonify
from backend.pipeline.flow_tracker import tracker
from backend.mitigation.state_machine import state_machine
from backend.database.db import query
from backend.models import loader

bp = Blueprint("ip_detail", __name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_active(src_ip: str) -> bool:
    # Check if IP is currently in state machine (phase 1-4 = active mitigation)
    try:
        state = state_machine._states.get(src_ip)
        return state is not None
    except Exception:
        return False


def _build_live_features(src_ip: str) -> dict | None:
    # Pull real-time features from flow tracker + inference cache.
    # Returns None if either is missing (stale = treat as inactive).
    flow   = tracker.get_flow(src_ip)
    cached = tracker.get_cached(src_ip)
    if not flow or not cached:
        return None

    fs        = flow.flow_stats or {}
    flags     = fs.get("flags", 0)
    pkt_count = max(int(fs.get("packet_count", 0)), 1)
    syn_ratio = (flags & 0x02) / pkt_count if flags else 0.0

    # Pull live phase/priority from state machine
    state    = state_machine._states.get(src_ip)
    phase    = state.phase    if state else "—"
    priority = state.priority if state else "—"
    action   = state.action   if state else "—"

    return {
        "src_ip":   src_ip,
        "is_live":  True,
        "features": {
            "pkt_count":     fs.get("packet_count", 0),
            "syn_ratio":     round(syn_ratio, 4),
            "pps":           fs.get("packet_count_per_second", 0),
            "byte_rate":     fs.get("byte_count_per_second", 0),
            "active_flows":  tracker.active_count(),
            "sw_delta":      fs.get("switch_delta_pps", 0),
            "inter_arrival": fs.get("inter_arrival", 0),
            "unique_ports":  fs.get("unique_ports", 0),
            "duration_sec":  fs.get("flow_duration_sec", 0),
        },
        "ml": {
            "if_score":     cached.if_score,
            "is_anomaly":   cached.is_anomaly,
            "attack_class": cached.attack_class,
            "confidence":   round(cached.confidence * 100, 1),
        },
        "state": {
            "phase":         phase,
            "priority":      priority,
            "action_taken":  action,
            "offence_count": getattr(state, "offence_count", 0) if state else 0,
            "ban_level":     getattr(state, "ban_level", 0)     if state else 0,
            "first_seen":    None,
        },
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        "phase_history": [],
    }


def _build_db_features(src_ip: str) -> dict | None:
    # Pull last-known features from database for released/historical IPs.
    # Returns None if no data exists at all.

    # Most recent mitigation event — IF score, action, phase
    ev_rows = query("""
        SELECT timestamp, predicted_class, attack_vector, confidence,
               if_score, phase, priority, action_taken
        FROM mitigation_events
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    if not ev_rows:
        ev_rows = query("""
            SELECT timestamp, predicted_class, attack_vector, confidence,
                   if_score, phase, priority, action_taken
            FROM mitigation_events_archive
            WHERE src_ip = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip,))
    if not ev_rows:
        return None

    ev       = ev_rows[0]
    if_score = ev.get("if_score") or 0.0
    conf_raw = ev.get("confidence") or 0.0
    conf_pct = round(conf_raw * 100, 1) if conf_raw <= 1.0 else round(conf_raw, 1)

    # Real feature values from detection_features table
    feat_rows = query("""
        SELECT packet_count, packet_count_per_second, byte_count_per_second,
               flow_duration_sec, flags, disp_pakt, disp_interval,
               gsp, gfe, mean_pkt, mean_byte
        FROM detection_features
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    feat = feat_rows[0] if feat_rows else {}

    pkt_count    = max(int(feat.get("packet_count", 0) or 0), 1)
    flags        = int(feat.get("flags", 0) or 0)
    syn_ratio    = round((flags & 0x02) / pkt_count, 4) if flags else 0.0
    gfe          = feat.get("gfe") or 0
    gsp          = max(feat.get("gsp") or 1, 1)
    unique_ports = int(gfe / gsp) if gsp else 0
    disp_pakt    = max(feat.get("disp_pakt") or 1, 1)
    disp_interval = feat.get("disp_interval") or 0
    inter_arrival = round(disp_interval / disp_pakt, 6)

    # ip_attack_history — offence/ban/phase metadata
    hist = query("""
        SELECT offence_count, ban_level, phase_reached, first_seen, priority
        FROM ip_attack_history
        WHERE src_ip = ?
        ORDER BY unblocked_at DESC LIMIT 1
    """, (src_ip,))
    h = hist[0] if hist else {}

    # Phase history — all distinct phase transitions
    phase_rows = query("""
        SELECT timestamp, phase, action_taken, attack_vector
        FROM mitigation_events WHERE src_ip = ?
        ORDER BY timestamp ASC
    """, (src_ip,))
    if not phase_rows:
        phase_rows = query("""
            SELECT timestamp, phase, action_taken, attack_vector
            FROM mitigation_events_archive WHERE src_ip = ?
            ORDER BY timestamp ASC
        """, (src_ip,))

    # Deduplicate phase transitions — keep first per (phase, action) pair
    seen   = set()
    phases = []
    for pr in phase_rows:
        key = (pr.get("phase"), pr.get("action_taken"))
        if key not in seen:
            seen.add(key)
            phases.append({
                "timestamp":     pr.get("timestamp"),
                "phase":         pr.get("phase") or "—",
                "action_taken":  pr.get("action_taken") or "—",
                "attack_vector": pr.get("attack_vector") or "—",
            })

    return {
        "src_ip":   src_ip,
        "is_live":  False,
        "features": {
            "pkt_count":     feat.get("packet_count", 0) or 0,
            "syn_ratio":     syn_ratio,
            "pps":           feat.get("packet_count_per_second", 0) or 0,
            "byte_rate":     feat.get("byte_count_per_second", 0) or 0,
            "active_flows":  gfe,
            "sw_delta":      round(feat.get("mean_pkt") or 0, 2),
            "inter_arrival": inter_arrival,
            "unique_ports":  unique_ports,
            "duration_sec":  feat.get("flow_duration_sec", 0) or 0,
        },
        "ml": {
            "if_score":     if_score,
            "is_anomaly":   True,
            "attack_class": ev.get("attack_vector") or "—",
            "confidence":   conf_pct,
        },
        "state": {
            "phase":         ev.get("phase") or h.get("phase_reached") or "—",
            "priority":      ev.get("priority") or h.get("priority") or "—",
            "action_taken":  ev.get("action_taken") or "—",
            "offence_count": h.get("offence_count", 0),
            "ban_level":     h.get("ban_level", 0),
            "first_seen":    h.get("first_seen"),
        },
        "phase_history":  phases,
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@bp.get("/api/ip_detail/<path:src_ip>/live")
def ip_detail_live(src_ip: str):
    # Real-time endpoint — only works for currently active IPs.
    # Called by ip-drawer.js every 2s when drawer is open and IP is active.
    # Returns 404 if IP is no longer in state machine so drawer stops polling.
    src_ip = src_ip.strip()
    if not _is_active(src_ip):
        return jsonify({"error": "IP not active"}), 404

    data = _build_live_features(src_ip)
    if not data:
        return jsonify({"error": "No live data"}), 404

    return jsonify(data)


@bp.get("/api/ip_detail/<path:src_ip>")
def ip_detail(src_ip: str):
    # Full detail endpoint — live if active, DB fallback if not.
    # is_live flag in response tells drawer whether to start polling.
    src_ip = src_ip.strip()

    # Try live first regardless of state machine — tracker may have fresh data
    if _is_active(src_ip):
        data = _build_live_features(src_ip)
        if data:
            return jsonify(data)

    # Fall back to DB
    data = _build_db_features(src_ip)
    if data:
        return jsonify(data)

    return jsonify({"error": "No data found for this IP"}), 404