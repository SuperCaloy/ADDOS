import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_TELEMETRY_ADDR, FLOOD_SYN_LIMIT, FLOOD_ICMP_LIMIT, FLOOD_UDP_LIMIT
from backend.pipeline import worker
from backend.pipeline.flood_prefilter import flood_filter
from backend.pipeline.entropy_analyzer import entropy_analyzer

log = logging.getLogger(__name__)

_RECONNECT_DELAY_S = 3.0
_RECV_TIMEOUT_MS   = 1000

# --- Raw packet counter for UI stats ---
_raw_lock       = threading.Lock()
_raw_total_pkts = 0

# --- Connected switch count from ZMQ switch_count messages ---
_switch_count_lock  = threading.Lock()
_connected_switches = 0

# --- Cumulative packet count per flow key for delta tracking ---
# OVS packet_count is cumulative so we track prev value to get delta
_flow_prev_pkts: dict[tuple, int] = {}
_flow_lock = threading.Lock()

# --- Per-switch flow list buffer for TEA ---
# Accumulates flow stats per dpid within one poll cycle
# TEA needs the full list of flows per switch to compute entropy
_switch_flows: dict[int, list[dict]] = {}
_switch_flows_lock = threading.Lock()


def get_raw_counts() -> dict:
    with _raw_lock:
        return {"raw_total": _raw_total_pkts}


def get_switch_count() -> int:
    with _switch_count_lock:
        return _connected_switches


def _reset_flow_state() -> None:
    """Reset all per-flow state on ZMQ reconnect."""
    global _raw_total_pkts
    with _flow_lock:
        _flow_prev_pkts.clear()
    with _raw_lock:
        _raw_total_pkts = 0
    with _switch_flows_lock:
        _switch_flows.clear()
    log.info("ZMQ receiver: flow state reset on reconnect")


def _build_synthetic_flow_stats(proto: str, limit: int) -> dict:
    """
    Build a fake flow_stats dict for a prefilter-tripped IP.
    Used so the worker gets something meaningful to feed into IF.
    Protocol number: ICMP=1, TCP=6, UDP=17
    """
    proto_num = {"SYN": 6, "ICMP": 1, "UDP": 17}.get(proto, 0)
    avg_bytes  = {"SYN": 60, "ICMP": 84, "UDP": 48}.get(proto, 60)
    return {
        "packet_count":            limit,
        "packet_count_per_second": float(limit),
        "switch_delta_pps":        float(limit),
        "ip_proto":                proto_num,
        "src_port":                0,
        "dst_port":                80,
        "byte_count":              limit * avg_bytes,
        "byte_count_per_second":   float(limit * avg_bytes),
        "flow_duration_sec":       1.0,
        "flow_duration_nsec":      0,
    }


def _parse_and_route(raw: bytes) -> None:
    global _raw_total_pkts, _connected_switches

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    msg_type = msg.get("type")

    # ------------------------------------------------------------------
    # switch_count — update how many switches are connected
    # ------------------------------------------------------------------
    if msg_type == "switch_count":
        with _switch_count_lock:
            _connected_switches = int(msg.get("connected", 0))
        return

    # ------------------------------------------------------------------
    # packet_in — real-time per-packet event from Ryu
    # This is where the flood pre-filter runs — no stats poll delay
    # ------------------------------------------------------------------
    elif msg_type == "packet_in":
        src_ip = msg.get("src_ip", "")
        proto  = msg.get("proto", "")

        if not src_ip:
            return

        # Map Ryu proto strings to our prefilter keys
        # SYN is a special case — only pure SYN packets (no ACK) count
        if proto == "TCP":
            if msg.get("tcp_flags_syn") and not msg.get("tcp_flags_ack"):
                # SYN flood tracking
                tripped = flood_filter.on_packet(src_ip, "SYN")
                if tripped:
                    flow_stats = _build_synthetic_flow_stats("SYN", FLOOD_SYN_LIMIT)
                    worker.submit(src_ip, flow_stats, {})
                    log.info("FloodPreFilter SYN tripped: %s → submitted to pipeline", src_ip)

            elif msg.get("tcp_flags_ack"):
                # ACK means handshake completed — reduce half-open count
                flood_filter.on_ack(src_ip)

        elif proto == "ICMP":
            # ICMP flood tracking — count every echo request
            tripped = flood_filter.on_packet(src_ip, "ICMP")
            if tripped:
                flow_stats = _build_synthetic_flow_stats("ICMP", FLOOD_ICMP_LIMIT)
                worker.submit(src_ip, flow_stats, {})
                log.info("FloodPreFilter ICMP tripped: %s → submitted to pipeline", src_ip)

        elif proto == "UDP":
            # UDP flood tracking — this is the key fix for slow UDP detection
            # Previously UDP had no prefilter so had to wait for stats poll
            tripped = flood_filter.on_packet(src_ip, "UDP")
            if tripped:
                flow_stats = _build_synthetic_flow_stats("UDP", FLOOD_UDP_LIMIT)
                worker.submit(src_ip, flow_stats, {})
                log.info("FloodPreFilter UDP tripped: %s → submitted to pipeline", src_ip)

    # ------------------------------------------------------------------
    # dropped_delta — real physical packet drop count from OVS
    # ------------------------------------------------------------------
    elif msg_type == "dropped_delta":
        src_ip = msg.get("src_ip", "")
        delta  = int(msg.get("delta", 0))
        if src_ip and delta > 0:
            try:
                from backend.pipeline.decision_engine import record_dropped_packets
                record_dropped_packets(src_ip, delta)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # flow_stats — per-flow telemetry from OVS stats poll (every 1s)
    # This is where TEA runs — after collecting flow data per switch
    # ------------------------------------------------------------------
    elif msg_type == "flow_stats":
        src_ip       = msg.get("src_ip", "")
        flow_stats   = msg.get("flow_stats", {})
        switch_stats = msg.get("switch_stats", {})
        dpid         = msg.get("dpid", 0)

        if not src_ip or not flow_stats:
            return

        pkt_count_cumulative = int(flow_stats.get("packet_count", 0))
        pps                  = float(flow_stats.get("packet_count_per_second", 0.0))

        # Delta tracking — compute how many new packets arrived this interval
        flow_key = (src_ip, dpid)
        with _flow_lock:
            prev_count                = _flow_prev_pkts.get(flow_key, 0)
            delta_pkts                = max(pkt_count_cumulative - prev_count, 0)
            _flow_prev_pkts[flow_key] = pkt_count_cumulative

        # Accumulate this flow into the switch-level buffer for TEA
        with _switch_flows_lock:
            if dpid not in _switch_flows:
                _switch_flows[dpid] = []
            _switch_flows[dpid].append({
                "src_ip":                 src_ip,
                "packet_count_per_second": pps,
                "byte_count_per_second":  float(flow_stats.get("byte_count_per_second", 0.0)),
            })

        # Update raw total for UI
        with _raw_lock:
            _raw_total_pkts += delta_pkts

        # --- Gate check: should this flow go to the ML worker? ---
        MIN_PPS          = 0.5
        switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0))
        is_flood_mode    = switch_delta_pps >= 1.0

        crosses_threshold = (
            pkt_count_cumulative >= 1
            and (pps >= MIN_PPS or is_flood_mode)
        )

        if not crosses_threshold:
            return

        # Skip if this IP is already in Phase 2 or 3 — block rule is active
        try:
            from backend.mitigation.state_machine import state_machine as _sm
            _ip_state = _sm._states.get(src_ip)
            if _ip_state is not None and _ip_state.phase >= 2:
                return
        except Exception:
            pass

        # --- TEA gate ---
        # Run entropy analysis on the accumulated flows for this switch.
        # We snapshot the current buffer, run TEA, then decide.
        with _switch_flows_lock:
            switch_flow_list = list(_switch_flows.get(dpid, []))

        tea_result = entropy_analyzer.update(dpid, switch_flow_list)

        # Check if prefilter already flagged this IP for any protocol
        already_flagged = flood_filter.is_flagged_any(src_ip)

        # TEA gate: should we submit to ML or skip?
        if not entropy_analyzer.should_submit(tea_result, already_flagged):
            log.debug(
                "TEA gate blocked submission for %s (conf=%s, flash_crowd=%s)",
                src_ip, tea_result["confidence"], tea_result["is_flash_crowd"]
            )
            return

        # Attach TEA result to flow_stats so worker/decision_engine can log it
        flow_stats["tea_attack_pattern"] = tea_result["is_attack_pattern"]
        flow_stats["tea_flash_crowd"]    = tea_result["is_flash_crowd"]
        flow_stats["tea_confidence"]     = tea_result["confidence"]
        flow_stats["tea_div_entropy"]    = tea_result["diversity_entropy"]
        flow_stats["tea_pkt_entropy"]    = tea_result["packetrate_entropy"]

        worker.submit(src_ip, flow_stats, switch_stats)


def _clear_switch_flow_buffers() -> None:
    """
    Clear the per-switch flow accumulation buffers.
    Call this once per polling cycle after all flow_stats for a switch
    have been processed — prevents old flows from polluting the next window.
    This is called from the receiver loop on a timer.
    """
    with _switch_flows_lock:
        _switch_flows.clear()


def _receiver_loop() -> None:
    ctx = zmq.Context.instance()

    # Timer to clear switch flow buffers once per second
    # Aligns with the Ryu stats poll interval
    _last_buffer_clear = time.monotonic()

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
                    _parse_and_route(raw)

                    # Clear flow buffers once per second so TEA gets fresh data
                    now = time.monotonic()
                    if now - _last_buffer_clear >= 1.0:
                        _clear_switch_flow_buffers()
                        flood_filter.purge_stale()
                        _last_buffer_clear = now

                except zmq.Again:
                    pass
                except zmq.ZMQError as e:
                    log.warning("ZMQ recv error: %s — reconnecting", e)
                    break

        except zmq.ZMQError as e:
            log.warning("ZMQ connect failed: %s — retry in %ss", e, _RECONNECT_DELAY_S)
        finally:
            sock.close()

        time.sleep(_RECONNECT_DELAY_S)


def start() -> None:
    t = threading.Thread(target=_receiver_loop, name="zmq-receiver", daemon=True)
    t.start()
    log.info("ZMQ receiver thread started (addr=%s)", ZMQ_TELEMETRY_ADDR)