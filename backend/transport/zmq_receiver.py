# ZeroMQ telemetry receiver consuming flow statistics and switch counts from Ryu.
# Parses switch statistics, tracks packet rates, and dispatches to pipeline worker and TEA.
import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_TELEMETRY_ADDR, ML_ENABLED, FLOW_FIELD_MAX

# Whitelisted IPs are never flood-filtered or submitted to ML (h26 = victim server, h27 = sinkhole). Without this, baseline pings to h26 trip the burst window and flag it as an attacker.
_WHITELIST_IPS = {"10.0.0.26", "10.0.0.27"}
from backend.pipeline import worker
from backend.pipeline.flood_prefilter import flood_filter
from backend.pipeline.entropy_analyzer import entropy_analyzer
from backend.mitigation.state_machine import state_machine

log = logging.getLogger(__name__)

_RECONNECT_DELAY_S = 3.0
_RECV_TIMEOUT_MS   = 1000

# Raw packet counter for UI stats
_raw_lock       = threading.Lock()
_raw_total_pkts = 0

# Total system PPS (packets per second)
_pps_lock = threading.Lock()
_total_pps = 0.0

# Connected switch count from ZMQ switch_count messages
_switch_count_lock  = threading.Lock()
_connected_switches = 0

# Cumulative packet count per flow key for delta tracking
# OVS packet_count is cumulative so we track prev value to get delta
_flow_prev_pkts: dict[tuple, int] = {}
_flow_lock = threading.Lock()

# Per-switch flow list buffer for TEA, one poll cycle at a time.
_switch_flows: dict[int, list[dict]] = {}
_switch_flows_lock = threading.Lock()


def get_raw_counts() -> dict:
    with _raw_lock:
        return {"raw_total": _raw_total_pkts}


# Return current total system packets per second and reset.
def get_total_pps() -> float:
    global _total_pps
    with _pps_lock:
        result = _total_pps
        _total_pps = 0.0
    return result


def _reset_flow_state() -> None:
    # Clear per-flow delta tracking and switch buffers on reconnect.
    # raw_total_pkts is not reset, it accumulates for the full session.
    with _flow_lock:
        _flow_prev_pkts.clear()
    with _switch_flows_lock:
        _switch_flows.clear()
    log.info("ZMQ receiver: flow state reset on reconnect (raw_total preserved)")





# Numeric flow fields reachable from attacker-side telemetry; clamped
# so a crafted huge/negative value cannot poison features or baselines.
_FLOW_NUMERIC_FIELDS = (
    "packet_count",
    "byte_count",
    "packet_count_per_second",
    "byte_count_per_second",
    "switch_delta_pps",
)


def _sanitize_flow_stats(flow_stats: dict) -> dict:
    if not isinstance(flow_stats, dict):
        return flow_stats
    for field in _FLOW_NUMERIC_FIELDS:
        if field not in flow_stats:
            continue
        value = flow_stats[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            flow_stats[field] = 0.0
        elif value < 0:
            flow_stats[field] = 0.0
        elif value > FLOW_FIELD_MAX:
            flow_stats[field] = FLOW_FIELD_MAX
        else:
            flow_stats[field] = float(value)
    return flow_stats


def _handle_switch_count(msg: dict) -> None:
    # Updates the active connected switch count from Ryu controller telemetry.
    # Synchronized under switch count lock for thread-safe dashboard reporting.
    global _connected_switches
    with _switch_count_lock:
        _connected_switches = int(msg.get("connected", 0))


def _handle_packet_in(msg: dict) -> None:
    # Processes real-time packet-in notifications to detect early flood patterns.
    # Evaluates SYN, ICMP, and UDP flood prefilters before full flow stats arrive.
    src_ip = msg.get("src_ip", "")
    proto = msg.get("proto", "")

    if not src_ip or src_ip in _WHITELIST_IPS or not ML_ENABLED:
        return

    if proto == "TCP":
        if msg.get("tcp_flags_syn") and not msg.get("tcp_flags_ack"):
            tripped = flood_filter.on_packet(src_ip, "SYN")
            if tripped:
                log.info("FloodPreFilter SYN tripped: %s - awaiting real flow_stats", src_ip)
                state_machine.on_prefilter_trip(src_ip, flood_filter.is_correlated(src_ip))
        elif msg.get("tcp_flags_ack"):
            flood_filter.on_ack(src_ip)

    elif proto == "ICMP":
        tripped = flood_filter.on_packet(src_ip, "ICMP")
        if tripped:
            log.info("FloodPreFilter ICMP tripped: %s - awaiting real flow_stats", src_ip)
            state_machine.on_prefilter_trip(src_ip, flood_filter.is_correlated(src_ip))

    elif proto == "UDP":
        tripped = flood_filter.on_packet(src_ip, "UDP")
        if tripped:
            log.info("FloodPreFilter UDP tripped: %s - awaiting real flow_stats", src_ip)
            state_machine.on_prefilter_trip(src_ip, flood_filter.is_correlated(src_ip))


def _handle_dropped_delta(msg: dict) -> None:
    # Records physical packet drops reported by OpenFlow switches into decision engine.
    # Updates aggregate drop counters for system observability and reporting.
    # Also feeds per-IP liveness into the state machine so silent Time Bans
    # keep a live still-flooding signal for the reban gate. Best effort only.
    src_ip = msg.get("src_ip", "")
    delta = int(msg.get("delta", 0))
    if src_ip and delta > 0:
        try:
            from backend.pipeline.decision_engine import record_dropped_packets
            record_dropped_packets(src_ip, delta)
        except Exception:
            pass
        try:
            state_machine.update_drop_liveness(src_ip, delta)
        except Exception:
            pass


def _handle_flow_stats(msg: dict) -> None:
    # Processes 1-second per-flow telemetry from OpenFlow stats collectors.
    # Runs TEA analysis, evaluates tiered mitigation phases, and queues work for inference.
    global _raw_total_pkts, _total_pps

    src_ip = msg.get("src_ip", "")
    flow_stats = _sanitize_flow_stats(msg.get("flow_stats", {}))
    switch_stats = msg.get("switch_stats", {})
    dpid = msg.get("dpid", 0)

    if not src_ip or not flow_stats:
        return

    pkt_count_cumulative = int(flow_stats.get("packet_count", 0))
    pps = float(flow_stats.get("packet_count_per_second", 0.0))

    # Delta tracking: compute how many new packets arrived this interval
    flow_key = (src_ip, dpid)
    with _flow_lock:
        prev_count = _flow_prev_pkts.get(flow_key, 0)
        delta_pkts = max(pkt_count_cumulative - prev_count, 0)
        _flow_prev_pkts[flow_key] = pkt_count_cumulative

    # Accumulate this flow into the switch-level buffer for TEA
    with _switch_flows_lock:
        if dpid not in _switch_flows:
            _switch_flows[dpid] = []
        _switch_flows[dpid].append({
            "src_ip": src_ip,
            "packet_count_per_second": pps,
            "byte_count_per_second": float(flow_stats.get("byte_count_per_second", 0.0)),
            "packet_count": float(flow_stats.get("packet_count", 0.0)),
            "byte_count": float(flow_stats.get("byte_count", 0.0)),
            "ip_proto": int(flow_stats.get("ip_proto", 0)),
            "_ts": time.monotonic(),
        })

    # Update per-IP TEA profile for small-attacker detection
    if src_ip not in _WHITELIST_IPS:
        entropy_analyzer.update_ip(src_ip, pps, float(flow_stats.get("byte_count_per_second", 0.0)))

    # Update raw total for UI
    with _raw_lock:
        _raw_total_pkts += delta_pkts

    # Accumulate total PPS from flow pps
    with _pps_lock:
        _total_pps += pps

    # Skip TEA and ML inference if ML disabled; count packets directly
    if not ML_ENABLED:
        try:
            from backend.pipeline.decision_engine import on_result
            on_result(src_ip, 0.0, False, "Normal", 0.0,
                      flow_stats=flow_stats, switch_stats=switch_stats,
                      timed_out=False)
        except Exception:
            pass
        return

    if pkt_count_cumulative < 1:
        return

    # Tiered banned-IP handling (reduce GIL waste)
    _ip_phase = 0
    _ip_action = ""
    try:
        from backend.mitigation.state_machine import state_machine as _sm
        _ip_state = _sm.get_state(src_ip)
        if _ip_state is not None:
            _ip_phase = _ip_state.phase
            _ip_action = _ip_state.action_taken or ""
    except Exception:
        pass

    if _ip_phase == 3:
        # Blackhole: traffic dropped at switch; skip submission
        return

    if _ip_phase == 2 and _ip_action == "Time Ban":
        # Time Ban: full switch drop like Blackhole; skip submission so
        # attacker drop-telemetry cannot crowd normal traffic in the queue.
        # Unscored holds (action_taken "Holding (unscored...") still submit
        # below so they can be scored. Liveness for the reban gate comes
        # from per-IP drop-counter deltas, not worker results.
        return

    if _ip_phase == 2:
        # Time ban: refresh TEA evidence but skip expensive IF/RF inference
        flow_stats.pop("tea_eval_seq", None)
        flow_stats["tea_attack_pattern"] = False
        flow_stats["tea_flash_crowd"] = False
        flow_stats["tea_confidence"] = "low"
        flow_stats["tea_is_learned"] = False
        flow_stats["tea_size_var"] = 0.0
        flow_stats["tea_intensity_var"] = 0.0
        switch_stats["dpid"] = dpid
        worker.submit(src_ip, flow_stats, switch_stats)
        return

    # Snapshot switch buffer and evaluate entropy metrics
    with _switch_flows_lock:
        switch_flow_list = list(_switch_flows.get(dpid, []))
        if dpid in _switch_flows:
            _switch_flows[dpid] = []

    tea_result = entropy_analyzer.update(dpid, switch_flow_list)

    flow_stats["tea_attack_pattern"] = tea_result["is_attack_pattern"]
    flow_stats["tea_flash_crowd"] = tea_result["is_flash_crowd"]
    flow_stats["tea_confidence"] = tea_result["confidence"]
    flow_stats["tea_is_learned"] = tea_result["is_learned"]
    flow_stats["tea_size_var"] = tea_result["size_var"]
    flow_stats["tea_intensity_var"] = tea_result["intensity_var"]
    flow_stats["tea_eval_seq"] = tea_result.get("eval_seq")
    flow_stats["tea_flash_crowd_guidance"] = entropy_analyzer.get_flash_crowd_guidance()

    # Per-IP check for stealthy low-rate attackers
    ip_verdict = entropy_analyzer.get_ip_verdict(src_ip)
    if ip_verdict == "attack":
        if tea_result["is_learned"] and (
            tea_result["is_attack_pattern"]
            or tea_result.get("mahalanobis_distance", 0) > 3.0
        ):
            flow_stats["tea_attack_pattern"] = True
            flow_stats["tea_confidence"] = "moderate"
            log.info("TEA per-IP attack detected: %s", src_ip)
        else:
            log.debug("TEA per-IP shadow observation (learning): %s", src_ip)

    switch_stats["dpid"] = dpid
    worker.submit(src_ip, flow_stats, switch_stats)


def _parse_and_route(raw: bytes) -> None:
    # Deserializes incoming ZMQ messages and delegates to dedicated message handlers.
    # Safely ignores malformed payloads and unrecognized message categories.
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    msg_type = msg.get("type")
    if msg_type == "switch_count":
        _handle_switch_count(msg)
    elif msg_type == "packet_in":
        _handle_packet_in(msg)
    elif msg_type == "dropped_delta":
        _handle_dropped_delta(msg)
    elif msg_type == "flow_stats":
        _handle_flow_stats(msg)


# Evict per-switch flow entries older than one poll cycle (older than 1s).
def _clear_switch_flow_buffers() -> None:
    cutoff = time.monotonic() - 1.0
    with _switch_flows_lock:
        for dpid in list(_switch_flows):
            _switch_flows[dpid] = [
                f for f in _switch_flows[dpid] if f.get("_ts", 0) > cutoff
            ]
            if not _switch_flows[dpid]:
                del _switch_flows[dpid]


def _receiver_loop() -> None:
    ctx = zmq.Context.instance()

    # Timer to clear switch flow buffers once per second
    # Aligns with the Ryu stats poll interval
    _last_buffer_clear = time.monotonic()
    _last_profile_cleanup = time.monotonic()

    while True:
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, _RECV_TIMEOUT_MS)
        sock.setsockopt(zmq.LINGER, 0)

        try:
            sock.connect(ZMQ_TELEMETRY_ADDR)
            log.info("ZMQ receiver connected to %s", ZMQ_TELEMETRY_ADDR)
            _reset_flow_state()

            while True:
                try:
                    raw = sock.recv()
                    try:
                        _parse_and_route(raw)
                    except Exception:
                        log.exception("Error processing ZMQ message")

                    # Clear flow buffers once per second so TEA gets fresh data
                    now = time.monotonic()
                    if now - _last_buffer_clear >= 1.0:
                        _clear_switch_flow_buffers()
                        flood_filter.purge_stale()
                        # Zero-traffic latch recovery + IP profile TTL,
                        # piggybacked on the receiver's 1s cadence.
                        entropy_analyzer.idle_tick()
                        if now - _last_profile_cleanup >= 60.0:
                            entropy_analyzer.cleanup_stale_profiles()
                            _last_profile_cleanup = now
                        _last_buffer_clear = now

                except zmq.Again:
                    pass
                except zmq.ZMQError as e:
                    log.warning("ZMQ recv error: %s - reconnecting", e)
                    break

        except zmq.ZMQError as e:
            log.warning("ZMQ connect failed: %s - retry in %ss", e, _RECONNECT_DELAY_S)
        finally:
            sock.close()

        time.sleep(_RECONNECT_DELAY_S)


def start() -> None:
    t = threading.Thread(target=_receiver_loop, name="zmq-receiver", daemon=True)
    t.start()
    log.info("ZMQ receiver thread started (addr=%s)", ZMQ_TELEMETRY_ADDR)