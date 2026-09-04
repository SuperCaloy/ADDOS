from flask import Blueprint, jsonify
from backend.pipeline import decision_engine
from backend.pipeline.entropy_analyzer import entropy_analyzer
from backend.pipeline.worker import _queue
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.flood_prefilter import flood_filter
from backend.mitigation.state_machine import state_machine
from backend.mitigation.deception import deception
from backend.mitigation.resource_guard import resource_guard
from backend.models import loader
from backend.transport.zmq_receiver import get_total_pps
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


def _gather_pipeline_health() -> dict:
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

    return {
        "worker_queue_size": queue_size,
        "workers_active": workers_active,
        "cache_hit_rate": cache_hit_rate,
        "inference_latency": _latency_stats(),
        "flood_prefilter_flagged": len(flood_filter._flagged) if hasattr(flood_filter, '_flagged') else 0,
        "flood_prefilter_breakdown": _gather_prefilter_breakdown(),
        "flood_prefilter_correlated": len(flood_filter._correlated) if hasattr(flood_filter, '_correlated') else 0,
        "flood_prefilter_session": _gather_prefilter_session(),
        "total_pps": get_total_pps(),
    }


def _gather_prefilter_breakdown() -> dict:
    breakdown = {}
    if not hasattr(flood_filter, '_flagged'):
        return breakdown
    with flood_filter._lock:
        flagged_snapshot = list(flood_filter._flagged.items())
    for (ip, proto), reason in flagged_snapshot:
        if proto not in breakdown:
            breakdown[proto] = {"flagged_ips": 0, "burst": 0, "limit": 0, "correlated": 0, "flagged_ips_list": []}
        breakdown[proto]["flagged_ips"] += 1
        breakdown[proto]["flagged_ips_list"].append({"ip": ip, "reason": reason})
        if "burst" in reason.lower():
            breakdown[proto]["burst"] += 1
        elif "limit" in reason.lower() or "window" in reason.lower():
            breakdown[proto]["limit"] += 1
    return breakdown


def _gather_prefilter_session() -> dict:
    return {
        "session_spike": flood_filter._session_spike,
        "session_flagged_by_proto": dict(flood_filter._session_flagged_by_proto),
    }


def _gather_if_data(scan_log: list) -> dict:
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
        "normal": sum(1 for s in if_scores if s < loader.if_threshold),
        "anomaly": sum(1 for s in if_scores if s >= loader.if_threshold),
    }

    return {
        "threshold": loader.if_threshold,
        "recent_scores": if_recent,
        "score_distribution": if_dist,
    }


def _gather_rf_data(debug_log: list) -> dict:
    rf_recent = []
    rf_dist = {"SYN Flood": 0, "ICMP Flood": 0, "UDP Flood": 0, "Uncertain": 0}
    for entry in debug_log[:50]:
        cls = entry.get("attack_class", "Uncertain")
        rf_recent.append({
            "src_ip": entry.get("src_ip"),
            "attack_class": cls,
            "conf": entry.get("confidence"),
            "ts": entry.get("ts"),
            "is_anomaly": entry.get("is_anomaly", False),
        })
        rf_dist[cls] = rf_dist.get(cls, 0) + 1

    return {
        "conf_gate": loader.rf_conf_gate,
        "recent_classifications": rf_recent,
        "class_distribution": rf_dist,
    }


def _gather_tea_data() -> dict:
    tea_global = {}
    with entropy_analyzer._lock:
        state = entropy_analyzer._global_state
        size_base = state.size_base
        int_base = state.intensity_base
        proto_base = state.proto_base
        attack_sigma = size_base.dynamic_attack_sigma()
        crowd_sigma = size_base.dynamic_crowd_sigma()
        tea_global = {
            "learned": state.is_learned,
            "dynamic_attack_sigma": round(attack_sigma, 2),
            "dynamic_crowd_sigma": round(crowd_sigma, 2),
            "learning_interval": len(size_base._samples) if not size_base.is_learned else None,
            "learning_intervals": size_base._learn_n,
            "learning_rejected": size_base.rejected_count if not size_base.is_learned else None,
            "_locked": entropy_analyzer.is_locked,
            "_attack_latched": entropy_analyzer.attack_latched,
            "_fb_normal_streak": entropy_analyzer.fb_normal_streak,
            "_tea_normal_streak": entropy_analyzer.tea_normal_streak,
            "_would_block_count": entropy_analyzer.would_block_count,
            "alpha": round(size_base.alpha, 4),
            "size_baseline_history": [round(v, 4) for v in size_base.baseline_history],
            "intensity_baseline_history": [round(v, 4) for v in int_base.baseline_history],
            "proto_baseline_history": [round(v, 4) for v in proto_base.baseline_history],
        }
        curr = getattr(state, 'last_result', {})
        if curr:
            tea_global.update({
                "size_var": round(curr.get("size_var", 0), 4),
                "intensity_var": round(curr.get("intensity_var", 0), 4),
                "proto_entropy": round(curr.get("proto_entropy", 0), 4),
                "size_z": round(curr.get("size_zscore", 0), 2),
                "intensity_z": round(curr.get("intensity_zscore", 0), 2),
                "proto_z": round(curr.get("proto_zscore", 0), 2),
                "size_baseline": round(size_base.mean, 4) if size_base.mean is not None else None,
                "intensity_baseline": round(int_base.mean, 4) if int_base.mean is not None else None,
                "proto_baseline": round(proto_base.mean, 4) if proto_base.mean is not None else None,
                "is_attack": curr.get("is_attack_pattern", False),
                "is_flash_crowd": curr.get("is_flash_crowd", False),
                "uniform_share": round(curr.get("uniform_share", 0), 4),
                "mechanized_cluster": curr.get("mechanized_cluster", False),
                "uniform_backstop": curr.get("uniform_backstop", False),
                "pps_z": round(curr.get("pps_zscore", 0), 2),
                "pps_baseline": round(curr.get("pps_baseline", 0), 4),
                "pps_surge": curr.get("pps_surge", False),
                "size_surge": curr.get("size_surge", False),
                "intensity_surge": curr.get("intensity_surge", False),
                "unique_ips": curr.get("unique_ips", 0),
            })

        # Shadow baseline state
        shadow = state.shadow
        if shadow and shadow.active:
            shadow_baselines = shadow.baselines
            shadow_age = round(time.monotonic() - shadow.created_at, 1)
            tea_global["shadow"] = {
                "active": True,
                "sample_count": shadow.sample_count,
                "age_s": shadow_age,
                "learned": shadow_baselines.is_learned,
                "size_mean": round(shadow_baselines.size_base.mean, 4) if shadow_baselines.size_base.mean is not None else None,
                "intensity_mean": round(shadow_baselines.intensity_base.mean, 4) if shadow_baselines.intensity_base.mean is not None else None,
            }

    try:
        tea_global.update(entropy_analyzer.telemetry())
    except Exception:
        pass

    return {"global": tea_global}


def _gather_state_machine() -> dict:
    sm_states = {}
    for ip, ip_state in state_machine.get_states_snapshot().items():
        sm_states[ip] = {
            "phase": ip_state.phase,
            "phase_label": ip_state.phase_label(),
            "action": ip_state.action_taken,
            "ttl_sec": int(ip_state.ttl_expires_at - time.monotonic()) if ip_state.ttl_expires_at else None,
            "ban_level": ip_state.ban_level,
            "priority": ip_state.priority,
            "attack_vector": ip_state.attack_vector,
            "if_score": round(ip_state.if_score, 4),
            "confidence": round(ip_state.confidence, 3),
            "recent_pps": round(ip_state.recent_pps, 1),
            "transition_reason": ip_state.transition_reason,
        }
    return sm_states


def _gather_deception() -> dict:
    return {"active_sinkholes": deception.get_active_list()}


def _gather_resource_guard() -> dict:
    rg_tier = "NORMAL"
    if hasattr(resource_guard, '_tier'):
        rg_tier = resource_guard._tier
    elif hasattr(resource_guard, 'tier'):
        rg_tier = resource_guard.tier
    return {"tier": rg_tier}


def _gather_decision_data() -> dict:
    return {
        "stats": decision_engine.get_stats() if hasattr(decision_engine, 'get_stats') else {},
        "hold_stats": state_machine.get_hold_stats() if hasattr(state_machine, 'get_hold_stats') else {},
    }


@bp.get("/api/expert/live")
def expert_live():
    scan_log = decision_engine.get_scan_log()
    debug_log = decision_engine.get_debug_log()

    return jsonify({
        "pipeline": _gather_pipeline_health(),
        "if": _gather_if_data(scan_log),
        "rf": _gather_rf_data(debug_log),
        "tea": _gather_tea_data(),
        "state_machine": _gather_state_machine(),
        "deception": _gather_deception(),
        "resource_guard": _gather_resource_guard(),
        "decision_engine": _gather_decision_data(),
    })


def _record_worker_latency(latency_ms: float) -> None:
    record_latency_ms(latency_ms)
