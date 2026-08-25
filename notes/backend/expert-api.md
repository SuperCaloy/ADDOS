---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - backend
  - expert-mode
  - api
---

# Expert Mode Backend API

Added to support the **Expert Mode** visualization in the dashboard.

## New Endpoints

### `GET /api/expert/live`

Returns a complete snapshot of all algorithmic internals for live visualization.

**Response schema:**
```json
{
  "pipeline": {
    "worker_queue_size": 42,
    "workers_active": 6,
    "cache_hit_rate": 0.73,
    "inference_latency": {"p50_ms": 12.3, "p95_ms": 38.1, "p99_ms": 67.4, "samples": 234},
    "flood_prefilter_flagged": 3
  },
  "if": {
    "threshold": 0.6092241858026261,
    "recent_scores": [{"src_ip":"10.0.0.12","score":0.82,"anomaly":true,"ts":"14:23:11"}, ...],
    "score_distribution": {"normal": 142, "anomaly": 18}
  },
  "rf": {
    "conf_gate": 0.70,
    "recent_classifications": [{"src_ip":"10.0.0.12","class":"SYN Flood","conf":0.87,"ts":"14:23:11"}, ...],
    "class_distribution": {"SYN Flood": 11, "ICMP Flood": 5, "UDP Flood": 2, "Uncertain": 3}
  },
  "tea": {
    "global": {
      "is_attack": false,
      "is_flash_crowd": false,
      "learned": true,
      "size_baseline": 0.05,
      "intensity_baseline": 12.0,
      "size_var": 0.04,
      "intensity_var": 11.5,
      "size_z": -0.2,
      "intensity_z": -0.1,
      "unique_ips": 5
    },
    "per_ip_verdicts": {
      "10.0.0.1": "normal"
    }
  },
  "state_machine": {
    "10.0.0.12": {"phase":2,"phase_label":"Time Ban","action":"block","ttl_sec":120,"ban_level":2,"offence_count":1,"priority":"High","attack_vector":"SYN Flood","if_score":0.82,"confidence":0.87,"recent_pps":45.2}
  },
  "deception": {
    "active_sinkholes": [{"src_ip":"10.0.0.18","attack_vector":"Uncertain","if_score":0.65,"confidence":0.55,"obs_sec":12.3,"escalate_at_sec":30,"recent_pps":8.1}]
  },
  "resource_guard": {
    "tier": "OK"
  }
}
```

**Implementation:** `backend/api/expert.py` aggregates from `decision_engine` (scan/debug buffers), `entropy_analyzer`, `state_machine`, `deception`, `worker` (queue stats), `tracker` (cache stats), `resource_guard`. No DB queries; all in-memory singletons.

### SSE `expert` events (via `/api/events`)

Pushes incremental updates for live TEA/IF/RF data without polling:

```json
{
  "type": "expert",
  "ts": "14:23:11",
  "payload": {
    "tea_update": {
      "dpid": 0,
      "size_var": 0.04,
      "intensity_var": 11.5,
      "size_z": -0.2,
      "intensity_z": -0.1,
      "is_attack": false,
      "is_flash_crowd": false,
      "is_learned": true,
      "confidence": "low"
    }
  }
}
```

```json
{
  "type": "expert",
  "ts": "14:23:12",
  "payload": {
    "inference": {
      "src_ip": "10.0.0.12",
      "if_score": 0.83,
      "is_anomaly": true,
      "attack_class": "SYN Flood",
      "confidence": 0.88,
      "threshold": 0.6092
    }
  }
}
```

**Implementation:** `backend/api/events.py` adds `push_expert_event()` + `drain_expert_events()` added to SSE stream.

## Integration Points

### `backend/pipeline/entropy_analyzer.py`
- Added `_push_expert_event()` lazy import
- Calls `_push_expert_event()` in `update()` after computing TEA result

### `backend/pipeline/worker.py`
- Added `_push_expert_worker_event()` and `_record_worker_latency()` lazy imports
- Records inference latency via `_record_worker_latency()`
- Pushes expert event after each IF/RF inference with full result

### `backend/api/ip_detail.py`
- Added `entropy_analyzer` import
- `_build_live_features()` now returns `tea_ip_profile` with per-IP verdict, samples, PPS trend, entropy

### `backend/main.py`
- Registered `expert_bp` blueprint

## Files Modified/Added

| File | Change |
|---|---|
| `backend/api/expert.py` | **NEW**: blueprint with `/api/expert/live` |
| `backend/api/events.py` | Extended: `expert` SSE event type, `push_expert_event()`, `drain_expert_events()` |
| `backend/pipeline/entropy_analyzer.py` | Hooked: pushes TEA updates |
| `backend/pipeline/worker.py` | Hooked: pushes IF/RF inference results + latency |
| `backend/api/ip_detail.py` | Extended: `tea_ip_profile` in live response |
| `backend/main.py` | Registered expert blueprint |

## Related notes

- [[frontend/dashboard]]: Expert Mode UI consuming these endpoints
- [[overview/architecture]]: data flow integration