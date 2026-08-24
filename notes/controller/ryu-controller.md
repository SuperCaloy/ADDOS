---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - controller
  - ryu
---

# Ryu Controller

**File:** `controller/ryu_controller.py` (791 lines)

The OpenFlow 1.3 control-plane agent of the DDoS mitigation system. Built on the Ryu SDN framework with `eventlet.monkey_patch()`.

## Core Class

`FatTreeController(app_manager.RyuApp)`:
- `OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]`: OpenFlow 1.3 only.
- CPU affinity pinned to cores 0-3 via `os.sched_setaffinity`.
- Spawns `_stats_poll_loop` (1s stats poll) and `_command_listener` (ZMQ PULL on port 5556) as green threads via `ryu.lib.hub`.

## OpenFlow Event Handlers

| Handler | Event / Dispatcher | Role |
|---|---|---|
| `switch_features_handler` | `EventOFPSwitchFeatures`, `CONFIG_DISPATCHER` | Registers datapath in `self._datapaths`; pushes `{"type":"switch_count"}` to backend; **flushes stale rules** from prior sessions (priorities 0, 1, 80, 90, 100); re-arms first-poll bypass; installs **table-miss rule at priority 1** (`OFPP_CONTROLLER`, NO_BUFFER); pre-installs rate-limit meter |
| `switch_disconnect_handler` | `EventOFPStateChange`, `DEAD_DISPATCHER` | Removes datapath + all per-switch state |
| `packet_in_handler` | `EventOFPPacketIn`, `MAIN_DISPATCHER` | Runs throttled fast-path; ARP → learn MAC + flood; non-IPv4 (LLDP, IPv6) → learn + flood if unknown dst; IPv4 → `_handle_ipv4` |
| `flow_stats_reply_handler` | `EventOFPFlowStatsReply`, `MAIN_DISPATCHER` | Core telemetry aggregation |
| `port_stats_reply_handler` | `EventOFPPortStatsReply`, `MAIN_DISPATCHER` | Counts active ports (`rx_packets > 0`) into `_port_counts` |

## OpenFlow Rule Priorities & Table-Miss

Priority ordering (lowest to highest):
1. **Table-miss** (priority 1) → controller (NO_BUFFER)
2. **Post-clear permit** (priority 5) → flood (10s timeout so released IPs forward instantly while MAC table re-learns)
3. **Forwarding rule** (priority 10) → learned port (`idle_timeout=60`)
4. **Proto drop** (priority 50) → drops random-source floods matching `ip_proto`
5. **Rate limit** (priority 80) → meter ID 1 (`RATE_LIMIT_PPS`) + normal output
6. **Quarantine** (priority 90) → drop
7. **Block** (priority 100) → full drop (`instructions=[]`), with optional TTL

## Stats Collection & ZMQ Telemetry

- `_stats_poll_loop` runs every 1.0s, sends flow and port stats requests **staggered 40ms per switch** to avoid VMware burst load.
- Pushes to ZMQ `tcp://127.0.0.1:5555`:
  - `switch_count`
  - `packet_in` (SYN/ACK flags feed the backend flood pre-filter)
  - `flow_stats` (duration, pkts, bytes, rates, proto, tp_src/dst)
  - `switch_stats` (disp_pakt, mean_pkt, avg_durat, gfe, g_usip, rfip, gsp)
  - `dropped_delta` (real OVS physical drop counts)
- Whitelisted IPs `{"10.0.0.20", "10.0.0.21"}` are skipped from ML.

## Command Listener (ZMQ PULL, port 5556)

Handles `{"action", "src_ip", "ttl", "proto", "remove", "redirect_to"}`:
- `reset` → wipes all in-memory state.
- `block` / `rate_limit` / `quarantine` → adds IP to banned set + installs rules on **ALL switches** (attacker can enter from any edge).
- `clear` → removes banned IP, resets delta counters, starts cooldown, removes rules **scoped to last-seen switch**.
- `proto_block` → installs/removes priority-50 drop rule matching `ip_proto`.

> [!warning] Sinkhole redirect is a no-op
> The backend can send `{"action": "redirect"}` (for the sinkhole deception module), but `ryu_controller.py` has **no `redirect` branch** in `_apply_command`. The command is silently ignored. See [[known-issues/known-issues]].

## Related notes

- [[backend/transport]]: backend receiving side.
- [[backend/mitigation]]: backend side issuing commands.
- [[topology/topology-simulation]]: Mininet emulator connecting to this controller.