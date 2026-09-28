# IP detailed forensics and feature inspection API blueprint.
# Assembles real-time and historical flow metrics, TEA profiles, and mitigation phases for an IP.
import math
import re
from flask import Blueprint, jsonify, request
from backend.pipeline.flow_tracker import tracker
from backend.mitigation.state_machine import state_machine, PHASE_LABELS
from backend.pipeline.entropy_analyzer import entropy_analyzer
from backend.database.db import query
from backend.models import loader
from backend.models import baselines as signal_baselines
from backend.mitigation import behavioral

bp = Blueprint("ip_detail", __name__)

_PHASE_TO_ID = {label: pid for pid, label in PHASE_LABELS.items()}

# Writers also emit "Phase N" style labels (hold, re-offence). Map those too.
_PHASE_NUM_RE = re.compile(r"^\s*Phase\s*(\d+)", re.IGNORECASE)


def _phase_to_id(label) -> int:
    # Normalizes a DB phase value to its numeric id. Returns 0 when unknown
    # instead of raising, so one odd label never breaks the whole drawer.
    if isinstance(label, bool):
        return 0
    if isinstance(label, int):
        return label if label in PHASE_LABELS else 0
    if isinstance(label, str):
        hit = _PHASE_TO_ID.get(label)
        if hit is not None:
            return hit
        m = _PHASE_NUM_RE.match(label)
        if m:
            try:
                num = int(m.group(1))
            except ValueError:
                return 0
            return num if num in PHASE_LABELS else 0
    return 0

# Helper functions

def _read_tea_profile(src_ip: str) -> tuple[str, int, float, float]:
    tea_verdict = "uncertain"
    tea_samples = 0
    tea_pps_trend = 0.0
    tea_entropy = 0.0
    try:
        tea_verdict = entropy_analyzer.get_ip_verdict(src_ip)
        with entropy_analyzer._lock:
            profile = entropy_analyzer._ip_profiles.get(src_ip)
            if profile:
                tea_samples = len(profile._pps_samples)
                if len(profile._pps_samples) >= 2:
                    tea_pps_trend = profile._pps_samples[-1] - profile._pps_samples[0]
                pps_list = list(profile._pps_samples)
                pps_mean = sum(pps_list) / len(pps_list) if pps_list else 0.0
                pps_var = sum((x - pps_mean) ** 2 for x in pps_list) / len(pps_list) if pps_list else 0.0
                tea_entropy = math.sqrt(max(pps_var, 1e-9))
    except Exception:
        pass
    return tea_verdict, tea_samples, tea_pps_trend, tea_entropy

def _is_active(src_ip: str) -> bool:
    # Check if IP is currently in state machine (phase 1-3 = active mitigation)
    try:
        return state_machine.is_active(src_ip)
    except Exception:
        return False


def _calc_derived_features(stats: dict) -> dict:
    # Computes derived mathematical signals from raw flow packet and byte telemetry.
    # Returns normalized metrics for packet size uniformity, port entropy, and intensities.
    raw_pkts = stats.get("packet_count", 0) or 0
    pkt_count = max(int(raw_pkts), 1)
    byte_count = stats.get("byte_count", 0) or 0
    pps = stats.get("packet_count_per_second", 0) or 0
    byte_rate = float(stats.get("byte_count_per_second", 0) or 0)
    duration = stats.get("flow_duration_sec", 0) or 0

    bytes_per_packet = stats.get("bytes_per_packet")
    if bytes_per_packet is None:
        bytes_per_packet = round(byte_count / pkt_count, 1)

    pkt_size_uniformity = round(math.log1p(max(bytes_per_packet / (byte_rate + 1), 0)), 4)

    tp_src = float(stats.get("tp_src", 0) or 0)
    tp_dst = float(stats.get("tp_dst", 0) or 0)
    port_entropy = round(tp_src / (tp_dst + 1), 4)

    pkt_byte_rate_ratio = round((pps or 0) / (byte_rate or 1), 4)
    flow_intensity = round(math.log1p(max(raw_pkts * byte_rate, 0)), 4)
    bytes_per_duration = round(byte_count / max(duration or 1, 1), 4)
    flow_src_intensity = round(math.log1p(max(raw_pkts * pps, 0)), 4)

    return {
        "bytes_per_packet": bytes_per_packet,
        "pkt_size_uniformity": pkt_size_uniformity,
        "port_entropy": port_entropy,
        "pkt_byte_rate_ratio": pkt_byte_rate_ratio,
        "flow_intensity": flow_intensity,
        "bytes_per_duration": bytes_per_duration,
        "flow_src_intensity": flow_src_intensity,
        "tp_src": tp_src,
        "tp_dst": tp_dst,
    }


def _signal_blocks(stats: dict) -> dict:
    # Training derived normal references plus per-flow deviations for
    # Threat Analysis signal cards. Additive only; never breaks the drawer.
    refs = signal_baselines.references_from_artifacts()
    quantities = signal_baselines.signal_quantities(stats)
    deviations = signal_baselines.deviations_for(quantities, refs)
    return {
        'baselines': {
            key: {'median': round(ref['median'], 4), 'iqr': round(ref['iqr'], 4)}
            for key, ref in refs.items()
        },
        'deviations': {key: round(dev, 3) for key, dev in deviations.items()},
    }


def _to_phase_history(rows: list) -> list:
    # Deduplicates phase transitions, keeping the first row per
    # (phase, action) pair so escalations read as a short trail.
    seen = set()
    phases = []
    for pr in rows or []:
        key = (pr.get("phase"), pr.get("action_taken"))
        if key not in seen:
            seen.add(key)
            phases.append({
                "timestamp": pr.get("timestamp"),
                "phase": pr.get("phase") or 0,
                "action_taken": pr.get("action_taken") or "--",
                "attack_vector": pr.get("attack_vector") or "--",
                "event_type": pr.get("event_type"),
                "reason": pr.get("reason"),
            })
    return phases


def _session_phase_history(src_ip: str, session_id: str | None) -> list:
    # Phase trail scoped to one mitigation session when known, so a
    # re-offending IP shows the current incident, not older ones.
    if session_id:
        rows = query("""
            SELECT timestamp, phase, action_taken, attack_vector, event_type, reason
            FROM mitigation_events WHERE src_ip = ? AND session_id = ?
            ORDER BY timestamp ASC
        """, (src_ip, session_id))
        if rows:
            return _to_phase_history(rows)
    rows = query("""
        SELECT timestamp, phase, action_taken, attack_vector, event_type, reason
        FROM mitigation_events WHERE src_ip = ?
        ORDER BY timestamp ASC
    """, (src_ip,))
    if not rows:
        rows = query("""
            SELECT timestamp, phase, action_taken, attack_vector, event_type, reason
            FROM mitigation_events_archive WHERE src_ip = ?
            ORDER BY timestamp ASC
        """, (src_ip,))
    return _to_phase_history(rows)


def _empty_features() -> dict:
    # Zeroed flow telemetry for state-only views (flow stale or sinkholed).
    # Cards render as unavailable instead of showing another incident's data.
    return {
        "pkt_count": 0,
        "byte_count": 0,
        "pps": 0,
        "byte_rate": 0,
        "active_flows": tracker.active_count(),
        "duration_sec": 0,
        "bytes_per_packet": 0,
        "port_entropy": 0,
        "pkt_size_uniformity": 0,
        "flow_count_per_src": 0,
        "tp_src": 0,
        "tp_dst": 0,
        "ip_proto": 0,
        "pkt_byte_rate_ratio": 0,
        "flow_intensity": 0,
        "bytes_per_duration": 0,
        "flow_src_intensity": 0,
    }


def _build_active_state_features(src_ip: str, state) -> dict:
    # Live mitigation status for an active IP whose flow telemetry is stale
    # (blocked IPs stop sending traffic). Endpoint-layer fallback only, so
    # _build_live_features keeps returning None for stale flows.
    # Features come from the latest detection_features row so cards show
    # last-observed values instead of zeros. DB errors fall back to zeros.
    peak_if = max(float(state.if_score or 0.0), float(state.peak_if_score or 0.0))
    peak_conf = max(float(state.confidence or 0.0), float(state.peak_confidence or 0.0))
    tea_verdict, tea_samples, tea_pps_trend, tea_entropy = _read_tea_profile(src_ip)
    try:
        feat_rows = query("""
            SELECT packet_count, byte_count, packet_count_per_second,
                   byte_count_per_second, flow_duration_sec, flags,
                   bytes_per_packet, flow_count_per_src,
                   tp_src, tp_dst, ip_proto
            FROM detection_features
            WHERE src_ip = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip,))
    except Exception:
        feat_rows = []
    feat = feat_rows[0] if feat_rows else {}
    derived = _calc_derived_features(feat)
    features = _empty_features()
    if feat:
        features.update({
            "pkt_count": feat.get("packet_count", 0) or 0,
            "byte_count": feat.get("byte_count", 0) or 0,
            "pps": feat.get("packet_count_per_second", 0) or 0,
            "byte_rate": feat.get("byte_count_per_second", 0) or 0,
            "duration_sec": feat.get("flow_duration_sec", 0) or 0,
            "bytes_per_packet": derived["bytes_per_packet"],
            "port_entropy": derived["port_entropy"],
            "pkt_size_uniformity": derived["pkt_size_uniformity"],
            "flow_count_per_src": feat.get("flow_count_per_src", 0) or 0,
            "tp_src": derived["tp_src"],
            "tp_dst": derived["tp_dst"],
            "ip_proto": feat.get("ip_proto", 0) or 0,
            "pkt_byte_rate_ratio": derived["pkt_byte_rate_ratio"],
            "flow_intensity": derived["flow_intensity"],
            "bytes_per_duration": derived["bytes_per_duration"],
            "flow_src_intensity": derived["flow_src_intensity"],
        })
    return {
        "src_ip": src_ip,
        "is_live": True,
        "flow_stale": True,
        "features": features,
        "ml": {
            "if_score":     peak_if,
            "is_anomaly":   True,
            "attack_class": state.attack_vector or "--",
            "confidence":   round(peak_conf * 100, 4),
            "stale":        True,
            "age_s":        0.0,
        },
        "state": {
            "phase": state.phase,
            "phase_label": state.phase_label(),
            "priority": state.priority,
            "action_taken": state.action_taken,
            "ban_level": getattr(state, "ban_level", 0),
            "reputation_score": behavioral.get_decay_score(src_ip),
            "offence_count": behavioral.get_offence_count(src_ip),
            "first_seen": state.first_seen,
            "last_seen": None,
        },
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        "phase_history": _session_phase_history(src_ip, getattr(state, "session_id", None)),
        **_signal_blocks(feat),
        "tea_ip_profile": {
            "verdict": tea_verdict,
            "samples": tea_samples,
            "pps_trend": tea_pps_trend,
            "entropy": tea_entropy,
        },
    }


def _build_sinkhole_features(entry: dict) -> dict:
    # Live view for IPs under sinkhole observation. They live in the
    # deception module, not the state machine, so _is_active misses them.
    src_ip = entry.get("src_ip", "")
    vector = entry.get("attack_vector") or "--"
    elapsed = int(entry.get("elapsed_sec") or 0)
    remaining = int(entry.get("remaining_sec") or 0)
    tea_verdict, tea_samples, tea_pps_trend, tea_entropy = _read_tea_profile(src_ip)
    features = _empty_features()
    features["pps"] = float(entry.get("recent_pps") or 0)
    return {
        "src_ip": src_ip,
        "is_live": True,
        "flow_stale": True,
        "features": features,
        "ml": {
            "if_score":     float(entry.get("if_score") or 0.0),
            "is_anomaly":   True,
            "attack_class": vector,
            "confidence":   float(entry.get("confidence") or 0.0),
            "stale":        True,
            "age_s":        0.0,
        },
        "state": {
            "phase": 0,
            "phase_label": "Sinkhole",
            "priority": "Low",
            "action_taken": f"Sinkholed ({elapsed}s, {remaining}s left)",
            "ban_level": 0,
            "reputation_score": behavioral.get_decay_score(src_ip),
            "offence_count": behavioral.get_offence_count(src_ip),
            "first_seen": None,
            "last_seen": None,
        },
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        "phase_history": _session_phase_history(src_ip, None),
        "tea_ip_profile": {
            "verdict": tea_verdict,
            "samples": tea_samples,
            "pps_trend": tea_pps_trend,
            "entropy": tea_entropy,
        },
    }


def _build_session_features(src_ip: str, session_id: str, timestamp: str | None = None) -> dict | None:
    # Historical view of one specific audit event. Serves the clicked
    # session's own action, phase, and trail instead of latest-or-live.
    for table in ("mitigation_events", "mitigation_events_archive"):
        rows = query(f"""
            SELECT timestamp, predicted_class, attack_vector, confidence,
                   if_score, phase, priority, action_taken, event_type, reason,
                   session_id
            FROM {table}
            WHERE src_ip = ? AND session_id = ?
            ORDER BY timestamp ASC
        """, (src_ip, session_id))
        if rows:
            break
    if not rows and timestamp:
        for table in ("mitigation_events", "mitigation_events_archive"):
            rows = query(f"""
                SELECT timestamp, predicted_class, attack_vector, confidence,
                       if_score, phase, priority, action_taken, event_type, reason,
                       session_id
                FROM {table}
                WHERE src_ip = ? AND timestamp = ?
                ORDER BY timestamp ASC
            """, (src_ip, timestamp))
            if rows:
                break
    if not rows:
        return None

    target = rows[-1]
    if timestamp:
        for row in rows:
            if (row.get("timestamp") or "").strip() == timestamp.strip():
                target = row
                break

    if_score = float(target.get("if_score") or 0.0)
    conf_raw = float(target.get("confidence") or 0.0)
    attack_class = target.get("attack_vector") or "--"
    conf_pct = round(conf_raw * 100, 1) if conf_raw <= 1.0 else round(conf_raw, 1)

    feat_rows = []
    target_ts = (target.get("timestamp") or "").strip()
    if target_ts:
        try:
            import datetime as _dt
            _dt.datetime.fromisoformat(target_ts)
            feat_rows = query("""
                SELECT packet_count, byte_count, packet_count_per_second,
                       byte_count_per_second, flow_duration_sec, flags,
                       bytes_per_packet, flow_count_per_src,
                       tp_src, tp_dst, ip_proto
                FROM detection_features
                WHERE src_ip = ?
                ORDER BY ABS(strftime('%s', timestamp) - strftime('%s', ?)) ASC LIMIT 1
            """, (src_ip, target_ts))
        except ValueError:
            feat_rows = []
    if not feat_rows:
        feat_rows = query("""
            SELECT packet_count, byte_count, packet_count_per_second,
                   byte_count_per_second, flow_duration_sec, flags,
                   bytes_per_packet, flow_count_per_src,
                   tp_src, tp_dst, ip_proto
            FROM detection_features
            WHERE src_ip = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip,))
    feat = feat_rows[0] if feat_rows else {}
    derived = _calc_derived_features(feat)

    hist = query("""
        SELECT ban_level, phase_reached, first_seen, unblocked_at,
               priority, offence_count, reputation_score
        FROM ip_attack_history
        WHERE src_ip = ?
        ORDER BY unblocked_at DESC LIMIT 1
    """, (src_ip,))
    h = hist[0] if hist else {}

    action = target.get("action_taken") or "--"
    tea_verdict, tea_samples, tea_pps_trend, tea_entropy = _read_tea_profile(src_ip)

    return {
        "src_ip": src_ip,
        "is_live": False,
        "session_id": target.get("session_id") or session_id,
        "event_timestamp": target.get("timestamp"),
        "snapshot_at": target.get("timestamp"),
        "features": {
            "pkt_count": feat.get("packet_count", 0) or 0,
            "byte_count": feat.get("byte_count", 0) or 0,
            "pps": feat.get("packet_count_per_second", 0) or 0,
            "byte_rate": feat.get("byte_count_per_second", 0) or 0,
            "bytes_per_packet": derived["bytes_per_packet"],
            "port_entropy": derived["port_entropy"],
            "pkt_size_uniformity": derived["pkt_size_uniformity"],
            "duration_sec": feat.get("flow_duration_sec", 0) or 0,
            "flow_count_per_src": feat.get("flow_count_per_src", 0) or 0,
            "tp_src": derived["tp_src"],
            "tp_dst": derived["tp_dst"],
            "ip_proto": feat.get("ip_proto", 0) or 0,
            "pkt_byte_rate_ratio": derived["pkt_byte_rate_ratio"],
            "flow_intensity": derived["flow_intensity"],
            "bytes_per_duration": derived["bytes_per_duration"],
            "flow_src_intensity": derived["flow_src_intensity"],
        },
        "ml": {
            "if_score":     if_score,
            "is_anomaly":   True,
            "attack_class": attack_class,
            "confidence":   conf_pct,
        },
        "state": {
            "phase":            _phase_to_id(target.get("phase")),
            "priority":         target.get("priority") or h.get("priority") or "--",
            "action_taken":     action,
            "ban_level":        h.get("ban_level", 0),
            "reputation_score": h.get("reputation_score", 0.0),
            "offence_count":    h.get("offence_count", 0),
            "first_seen":       h.get("first_seen"),
            "last_seen":        h.get("unblocked_at"),
        },
        "phase_history": _to_phase_history(rows),
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        **_signal_blocks(feat),
        "tea_ip_profile": {
            "verdict": tea_verdict,
            "samples": tea_samples,
            "pps_trend": tea_pps_trend,
            "entropy": tea_entropy,
        },
    }


def _build_live_features(src_ip: str, state=None) -> dict | None:
    # Pull real-time features from flow tracker with degrading verdict.
    # Requires a fresh flow only. ML prefers the valid inference cache and
    # falls back to the last remembered verdict marked stale, so telemetry
    # survives cache gaps instead of 404ing. Returns None when the flow is
    # missing, stale, or never scored.
    import time as _time
    from backend.config import FLOW_STALE_S
    flow = tracker.get_flow(src_ip)
    if not flow:
        return None
    flow_age_s = _time.monotonic() - flow.last_seen
    if flow_age_s > FLOW_STALE_S:
        return None

    cached = tracker.get_cached(src_ip)
    if cached is not None:
        raw_if = cached.if_score
        raw_conf = cached.confidence
        raw_class = cached.attack_class
        raw_anom = cached.is_anomaly
        is_stale = False
        age_s = 0.0
    else:
        verdict = tracker.last_verdict(src_ip)
        if verdict is None:
            return None
        raw_if = verdict["if_score"]
        raw_conf = verdict["confidence"]
        raw_class = verdict["attack_class"]
        raw_anom = verdict["is_anomaly"]
        is_stale = True
        age_s = round(verdict["age_s"], 1)

    # Resolve peak scores: prefer the highest observed across FlowTracker and IpState
    peak = tracker.get_peak(src_ip) or {}
    peak_if = float(peak.get("if_score", 0.0) or 0.0)
    peak_conf = float(peak.get("confidence", 0.0) or 0.0)
    peak_class = peak.get("attack_class") or raw_class

    if state is None:
        state = state_machine.get_state(src_ip)
    if state is not None:
        if getattr(state, "peak_if_score", 0.0) > peak_if:
            peak_if = float(state.peak_if_score)
        if getattr(state, "peak_confidence", 0.0) > peak_conf:
            peak_conf = float(state.peak_confidence)
            if state.attack_vector and state.attack_vector != "Uncertain":
                peak_class = state.attack_vector

    eff_if = max(raw_if, peak_if)
    eff_conf = max(raw_conf, peak_conf)
    eff_class = peak_class if eff_conf == peak_conf else raw_class

    ml = {
        "if_score":     eff_if,
        "is_anomaly":   raw_anom,
        "attack_class": eff_class,
        "confidence":   round(eff_conf * 100, 4),
        "stale":        is_stale,
        "age_s":        age_s,
    }

    fs = flow.flow_stats or {}
    derived = _calc_derived_features(fs)

    # Pull live phase/priority from state machine (locked accessor, copy) if not provided
    if state is None:
        state = state_machine.get_state(src_ip)
    phase = state.phase if state else 0
    priority = state.priority if state else "--"
    action = state.action_taken if state else "--"

    # TEA per-IP profile
    tea_verdict, tea_samples, tea_pps_trend, tea_entropy = _read_tea_profile(src_ip)

    return {
        "src_ip": src_ip,
        "is_live": True,
        "flow_age_s": round(flow_age_s, 1),
        "features": {
            "pkt_count": fs.get("packet_count", 0),
            "byte_count": fs.get("byte_count", 0),
            "pps": fs.get("packet_count_per_second", 0),
            "byte_rate": fs.get("byte_count_per_second", 0),
            "active_flows": tracker.active_count(),
            "duration_sec": fs.get("flow_duration_sec", 0),
            "bytes_per_packet": derived["bytes_per_packet"],
            "port_entropy": derived["port_entropy"],
            "pkt_size_uniformity": derived["pkt_size_uniformity"],
            # Expert trace fields
            "flow_count_per_src": fs.get("flow_count_per_src", 0),
            "tp_src": derived["tp_src"],
            "tp_dst": derived["tp_dst"],
            "ip_proto": float(fs.get("ip_proto", 0)),
            "pkt_byte_rate_ratio": derived["pkt_byte_rate_ratio"],
            "flow_intensity": derived["flow_intensity"],
            "bytes_per_duration": derived["bytes_per_duration"],
            "flow_src_intensity": derived["flow_src_intensity"],
        },
        "ml": ml,
        "state": {
            "phase": phase,
            "phase_label": state.phase_label() if state else "--",
            "priority": priority,
            "action_taken": action,

            "ban_level": getattr(state, "ban_level", 0) if state else 0,
            "reputation_score": behavioral.get_decay_score(src_ip),
            "offence_count": behavioral.get_offence_count(src_ip),
            "first_seen": state.first_seen if state else None,
            "last_seen": None,
            # Ban timing for duration labels (e.g. Time Ban (5m)).
            # Reconstructed from the same TTL the switch enforces.
            "ttl_remaining_sec": (
                max(0, int(state.ttl_expires_at - _time.monotonic()))
                if state is not None and state.ttl_expires_at is not None
                else None
            ),
            "time_in_phase_sec": (
                int(state.time_in_phase_sec()) if state is not None else None
            ),
        },
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        **_signal_blocks(fs),
        "phase_history": [],
        "tea_ip_profile": {
            "verdict": tea_verdict,
            "samples": tea_samples,
            "pps_trend": tea_pps_trend,
            "entropy": tea_entropy,
        },
    }


def _build_db_features(src_ip: str, as_historical: bool = False) -> dict | None:
    # Pull last-known features from database for released/historical IPs.
    # Prefers the release-moment snapshot (the final live frame verbatim).
    # Falls back to latest-row reconstruction for rows predating snapshots.
    # as_historical marks an explicitly requested historical view, which is
    # never live even if the IP has since re-offended. Returns None if no
    # data exists at all.

    from backend.database.writer import get_release_snapshot
    snapshot = get_release_snapshot(src_ip)
    if snapshot and snapshot.get("payload"):
        data = dict(snapshot["payload"])
        data["is_live"] = False
        data["snapshot_at"] = snapshot.get("released_at")
        data["release_reason"] = snapshot.get("reason")
        return data

    archive_table = "mitigation_events"
    ev_rows = query("""
        SELECT timestamp, predicted_class, attack_vector, confidence,
               if_score, phase, priority, action_taken
        FROM mitigation_events
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    if not ev_rows:
        archive_table = "mitigation_events_archive"
        ev_rows = query("""
            SELECT timestamp, predicted_class, attack_vector, confidence,
                   if_score, phase, priority, action_taken
            FROM mitigation_events_archive
            WHERE src_ip = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip,))
    if not ev_rows:
        return None

    ev = ev_rows[0]
    if_score = float(ev.get("if_score") or 0.0)
    conf_raw = float(ev.get("confidence") or 0.0)
    attack_class = ev.get("attack_vector") or "--"

    # Query peak scores observed across this IP history
    peak_ev = query(f"""
        SELECT MAX(if_score) AS max_if, MAX(confidence) AS max_conf
        FROM {archive_table}
        WHERE src_ip = ?
    """, (src_ip,))
    if peak_ev and peak_ev[0]:
        max_if = peak_ev[0].get("max_if")
        max_conf = peak_ev[0].get("max_conf")
        if max_if is not None and float(max_if) > if_score:
            if_score = float(max_if)
        if max_conf is not None and float(max_conf) > conf_raw:
            conf_raw = float(max_conf)
            class_row = query(f"""
                SELECT attack_vector FROM {archive_table}
                WHERE src_ip = ? AND confidence = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (src_ip, max_conf))
            if class_row and class_row[0].get("attack_vector"):
                attack_class = class_row[0]["attack_vector"]

    conf_pct = round(conf_raw * 100, 1) if conf_raw <= 1.0 else round(conf_raw, 1)

    # Real feature values from detection_features table
    feat_rows = query("""
        SELECT packet_count, byte_count, packet_count_per_second,
               byte_count_per_second, flow_duration_sec, flags,
               bytes_per_packet, flow_count_per_src,
               tp_src, tp_dst, ip_proto
        FROM detection_features
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    feat = feat_rows[0] if feat_rows else {}
    derived = _calc_derived_features(feat)

    # ip_attack_history: offence/ban/phase metadata
    hist = query("""
        SELECT ban_level, phase_reached, first_seen, unblocked_at,
               priority, offence_count, reputation_score
        FROM ip_attack_history
        WHERE src_ip = ?
        ORDER BY unblocked_at DESC LIMIT 1
    """, (src_ip,))
    h = hist[0] if hist else {}

    # Phase history: all distinct phase transitions
    phase_rows = query("""
        SELECT timestamp, phase, action_taken, attack_vector, event_type, reason
        FROM mitigation_events WHERE src_ip = ?
        ORDER BY timestamp ASC
    """, (src_ip,))
    if not phase_rows:
        phase_rows = query("""
            SELECT timestamp, phase, action_taken, attack_vector, event_type, reason
            FROM mitigation_events_archive WHERE src_ip = ?
            ORDER BY timestamp ASC
        """, (src_ip,))
    phases = _to_phase_history(phase_rows)

    # TEA per-IP profile
    tea_verdict, tea_samples, tea_pps_trend, tea_entropy = _read_tea_profile(src_ip)

    # DB phase is string label, convert to numeric
    db_phase = _phase_to_id(ev.get("phase") or h.get("phase_reached"))

    return {
        "src_ip": src_ip,
        "is_live": _is_active(src_ip) and not as_historical,
        "features": {
            "pkt_count": feat.get("packet_count", 0) or 0,
            "byte_count": feat.get("byte_count", 0) or 0,
            "pps": feat.get("packet_count_per_second", 0) or 0,
            "byte_rate": feat.get("byte_count_per_second", 0) or 0,
            "bytes_per_packet": derived["bytes_per_packet"],
            "port_entropy": derived["port_entropy"],
            "pkt_size_uniformity": derived["pkt_size_uniformity"],
            "duration_sec": feat.get("flow_duration_sec", 0) or 0,
            # Expert trace fields
            "flow_count_per_src": feat.get("flow_count_per_src", 0) or 0,
            "tp_src": derived["tp_src"],
            "tp_dst": derived["tp_dst"],
            "ip_proto": feat.get("ip_proto", 0) or 0,
            "pkt_byte_rate_ratio": derived["pkt_byte_rate_ratio"],
            "flow_intensity": derived["flow_intensity"],
            "bytes_per_duration": derived["bytes_per_duration"],
            "flow_src_intensity": derived["flow_src_intensity"],
        },
        "ml": {
            "if_score":     if_score,
            "is_anomaly":   True,
            "attack_class": attack_class,
            "confidence":   conf_pct,
        },
        "state": {
            "phase":            db_phase,
            "priority":         ev.get("priority") or h.get("priority") or "--",
            "action_taken":     ev.get("action_taken") or "--",

            "ban_level":        h.get("ban_level", 0),
            "reputation_score": h.get("reputation_score", 0.0),
            "offence_count":    h.get("offence_count", 0),
            "first_seen":       h.get("first_seen"),
            "last_seen":        h.get("unblocked_at"),
        },
        "phase_history":  phases,
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
        **_signal_blocks(feat),
        "tea_ip_profile": {
            "verdict": tea_verdict,
            "samples": tea_samples,
            "pps_trend": tea_pps_trend,
            "entropy": tea_entropy,
        },
    }


# Endpoints

@bp.get("/api/ip_detail/<path:src_ip>/live")
def ip_detail_live(src_ip: str):
    # Real-time endpoint: only works for currently active IPs.
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
    # Full detail endpoint.
    # Routing, in order:
    # 1. ?session_id=... serves one specific audit event (historical, never live).
    # 2. ?historical=1 or ?snapshot=1 serves the release snapshot or legacy
    #    rows, even if the IP has re-offended and is active again.
    # 3. Active IPs serve live flow telemetry, or live state-machine status
    #    with flow_stale when flows are stale. Never another incident's data.
    # 4. Sinkholed IPs serve their live deception status.
    # 5. Otherwise DB fallback for released IPs, 404 when nothing exists.
    # is_live flag in response tells drawer whether to start polling.
    src_ip = src_ip.strip()
    force_historical = request.args.get("historical") in ("1", "true") or request.args.get("snapshot") in ("1", "true")

    session_id = (request.args.get("session_id") or "").strip()
    if session_id:
        data = _build_session_features(
            src_ip, session_id,
            (request.args.get("timestamp") or "").strip() or None)
        if data:
            return jsonify(data)
        return jsonify({"error": "No event found for this session"}), 404

    # Try live first unless historical snapshot is explicitly requested
    if not force_historical and _is_active(src_ip):
        data = _build_live_features(src_ip)
        if data:
            return jsonify(data)
        state = state_machine.get_state(src_ip)
        if state is not None:
            return jsonify(_build_active_state_features(src_ip, state))

    # Sinkholed IPs are active mitigations outside the state machine
    if not force_historical:
        from backend.mitigation.deception import deception
        entry = next(
            (e for e in deception.get_active_list()
             if (e.get("src_ip") or "") == src_ip),
            None)
        if entry is not None:
            return jsonify(_build_sinkhole_features(entry))

    # Fall back to DB (prefers release snapshot, falls back to legacy rows)
    data = _build_db_features(src_ip, as_historical=force_historical)
    if data:
        return jsonify(data)

    return jsonify({"error": "No data found for this IP"}), 404