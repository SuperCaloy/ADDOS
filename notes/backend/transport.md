---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - backend
  - transport
---

# Transport & Ingestion

**File:** `backend/transport/zmq_receiver.py`

Sole ingress point for all Ryu telemetry. Runs a persistent ZeroMQ **PULL** socket with reconnect logic (`_receiver_loop`), `_RECONNECT_DELAY_S = 3.0; resilient to Ryu being offline.

## Message routing (`_parse_and_route`)

| Message type | Handling |
|---|---|
| `switch_count` | Tracks connected switch count (`get_switch_count()`) |
| `packet_in` | Real-time per-packet events → runs the **flood prefilter** immediately (no stats-poll delay). TCP: only pure SYN counts; ACK reduces half-open count via `flood_filter.on_ack()`. ICMP: every echo request. UDP: every packet. On trip → `state_machine.on_prefilter_trip(src_ip, flood_filter.is_correlated(src_ip))`. Whitelist `{10.0.0.20 (victim), 10.0.0.21 (sinkhole)}` is never flood-filtered |
| `dropped_delta` | Real OVS physical drop counts → `decision_engine.record_dropped_packets()` |
| `flow_stats` | Per-flow telemetry every ~1s. Tracks cumulative `packet_count` deltas per `(src_ip, dpid)`, buffers per-switch flow lists for TEA (cleared once/second), runs `entropy_analyzer.update(0, flows)`, attaches `tea_size_var`, `tea_intensity_var` (and other TEA fields), skips IPs already in state-machine phases 2/3, calls `worker.submit(src_ip, flow_stats, switch_stats)`. When `ML_ENABLED=False`: bypasses ML and calls `decision_engine.on_result()` directly with a "Normal" result so dashboard counters still move |

## Key exports

- `get_raw_counts()`: raw packet total.
- `get_switch_count()`.
- Module-level whitelist `_WHITELIST_IPS`.

## See also

- [[controller/ryu-controller]]: the producer side of this socket.
- [[backend/ml-pipeline]]: what happens to the flow_stats after submission.