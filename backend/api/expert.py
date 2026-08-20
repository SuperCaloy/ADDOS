from flask import Blueprint, jsonify
from backend.pipeline import decision_engine
from backend.pipeline.entropy_analyzer import entropy_analyzer
from backend.pipeline.worker import _queue
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.flood_prefilter import flood_filter
from backend.mitigation.state_machine import state_machine
from backend.mitigation.deception import deception
from backend.mitigation.resource_guard import resource_guard
import threading
import time

bp = Blueprint("expert", __name__)

_LATENCY_LOCK = threading.Lock()
_latency_samples = []

def record_latency_ms(latency_ms: float) -> None:
    with _LATENCY_LOCK:
        _latency_samples.append(latency_ms)
        if len(_latency_samples) > 500:
            _latency_samples.pop(0)


def _percentile(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _latency_stats():
    with _LATENCY_LOCK:
        vals = sorted(_latency_samples)
    return {
        "p50_ms": round(_percentile(vals, 0.50), 1),
        "p95_ms": round(_percentile(vals, 0.95), 1),
        "p99_ms": round(_percentile(vals, 0.99), 1),
        "samples": len(vals),
    }


@bp.get("/api/expert/live")
def expert_live():
    # Pipeline health
    queue_size = _queue.qsize()
    workers_active = 0
    try:
        from backend.pipeline.worker import _active_workers
        workers_active = len(_active_workers)
    except Exception:
        pass

    cache_hits = getattr(tracker, '_cache_hits', 0)
    cache_lookups = getattr(tracker, '_cache_lookups', 0)
    cache_hit_rate = round(cache_hits / max(cache_lookups, 1), 3)

    flood_flagged = len(flood_filter._flagged) if hasattr(flood_filter, '_flagged') else 0

    # IF recent scores from scan buffer
    scan_log = decision_engine.get_scan_log()
    if_recent = []
    for entry in scan_log[:50]:
        if_recent.append({
            "src_ip": entry.get("src_ip"),
            "score": entry.get("if_score"),
            "anomaly": entry.get("is_anomaly"),
            "ts": entry.get("ts"),
        })

    if_scores = [e.get("if_score", 0) for e in scan_log]
    if_dist = {
        "normal": sum(1 for s in if_scores if s < 0.6092),
        "anomaly": sum(1 for s in if_scores if s >= 0.6092),
    }

    # RF recent classifications
    debug_log = decision_engine.get_debug_log()
    rf_recent = []
    rf_dist = {"SYN Flood": 0, "ICMP Flood": 0, "UDP Flood": 0, "Uncertain": 0}
    for entry in debug_log[:50]:
        cls = entry.get("attack_class", "Uncertain")
        rf_recent.append({
            "src_ip": entry.get("src_ip"),
            "class": cls,
            "conf": entry.get("confidence"),
            "ts": entry.get("ts"),
        })
        rf_dist[cls] = rf_dist.get(cls, 0) + 1

    # TEA global state
    tea_global = {}
    with entropy_analyzer._lock:
        state = entropy_analyzer._global_state
        size_base = state.size_base
        int_base = state.intensity_base
        curr = getattr(state, 'last_result', {})
        if curr:
            tea_global = {
                "learned": size_base.is_learned,
                "size_var": round(curr.get("size_var", 0), 4),
                "intensity_var": round(curr.get("intensity_var", 0), 4),
                "size_z": round(curr.get("size_zscore", 0), 2),
                "intensity_z": round(curr.get("intensity_zscore", 0), 2),
                "size_baseline": round(size_base.mean, 4) if size_base.mean is not None else None,
                "intensity_baseline": round(int_base.mean, 4) if int_base.mean is not None else None,
                "is_attack": curr.get("is_attack_pattern", False),
                "is_flash_crowd": curr.get("is_flash_crowd", False),
                "unique_ips": curr.get("unique_ips", 0),
                "learning_interval": len(size_base._samples) if not size_base.is_learned else None,
            }

    # TEA per-IP verdicts
    tea_per_ip = {}
    with entropy_analyzer._lock:
        for ip, profile in entropy_analyzer._ip_profiles.items():
            tea_per_ip[ip] = profile.verdict()

    # State machine active states
    sm_states = {}
    for ip, ip_state in state_machine._states.items():
        sm_states[ip] = {
            "phase": ip_state.phase,
            "phase_label": ip_state.phase_label(),
            "action": ip_state.action_taken,
            "ttl_sec": int(ip_state.ttl_expires_at - time.monotonic()) if ip_state.ttl_expires_at else None,
            "ban_level": ip_state.ban_level,
            "offence_count": ip_state.offence_count,
            "priority": ip_state.priority,
            "attack_vector": ip_state.attack_vector,
            "if_score": round(ip_state.if_score, 4),
            "confidence": round(ip_state.confidence, 3),
            "recent_pps": round(ip_state.recent_pps, 1),
        }

    # Deception active sinkholes
    sinkholes = []
    for ip, entry in deception._entries.items():
        sinkholes.append({
            "src_ip": ip,
            "attack_vector": entry.attack_vector,
            "if_score": round(entry.if_score, 4),
            "confidence": round(entry.confidence, 3),
            "obs_sec": round(entry.elapsed(), 1),
            "escalate_at_sec": 30,
            "recent_pps": round(entry.recent_pps, 1),
        })

    # Resource guard tier
    rg_tier = "OK"
    if hasattr(resource_guard, '_tier'):
        rg_tier = resource_guard._tier

    return jsonify({
        "pipeline": {
            "worker_queue_size": queue_size,
            "workers_active": workers_active,
            "cache_hit_rate": cache_hit_rate,
            "inference_latency": _latency_stats(),
            "flood_prefilter_flagged": flood_flagged,
        },
        "if": {
            "threshold": 0.6092241858026261,
            "recent_scores": if_recent,
            "score_distribution": if_dist,
        },
        "rf": {
            "conf_gate": 0.70,
            "recent_classifications": rf_recent,
            "class_distribution": rf_dist,
        },
        "tea": {
            "global": tea_global,
            "per_ip_verdicts": tea_per_ip,
        },
        "state_machine": sm_states,
        "deception": {
            "active_sinkholes": sinkholes,
        },
        "resource_guard": {
            "tier": rg_tier,
        },
    })


# Called by worker to record inference latency
def _record_worker_latency(latency_ms: float) -> None:
    record_latency_ms(latency_ms)