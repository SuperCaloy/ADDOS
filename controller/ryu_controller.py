# eventlet must be patched before all other imports
import eventlet
eventlet.monkey_patch()

import os
import json
import time
import collections
import ipaddress

import zmq
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp, udp
from ryu.lib import hub
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.mitigation.traffic_filter import RATE_LIMIT_PPS
# ── ZMQ addresses ──────────────────────────────────────────────────────────
TELEMETRY_ADDR = "tcp://127.0.0.1:5555"
COMMAND_ADDR   = "tcp://127.0.0.1:5556"

# Stats poll interval in seconds
STATS_INTERVAL = 1.0

# IPs whose reply traffic should never be scored by the ML pipeline
_SKIP_SRC = {"10.0.0.20", "10.0.0.21"}

# Action → OVS drop priority mapping
_DROP_PRIORITY = {"block": 100, "quarantine": 90, "rate_limit": 80}

# All drop priorities including proto-level (50)
_ALL_DROP_PRIORITIES = (50, 80, 90, 100)

# OpenFlow Meter ID used for rate limiting — fixed ID, one meter per switch
_RATE_LIMIT_METER_ID = 1


class FatTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._init_system()
        self._init_zmq()
        self._init_state()
        hub.spawn(self._stats_poll_loop)
        hub.spawn(self._command_listener)

    # ── Initialisation helpers ─────────────────────────────────────────────

    def _init_system(self) -> None:
        os.sched_setaffinity(0, {0, 1, 2, 3})

    def _init_zmq(self) -> None:
        # Telemetry PUSH socket — sends flow stats and events to backend
        self._zmq_ctx  = zmq.Context()
        self._tel_sock = self._zmq_ctx.socket(zmq.PUSH)
        self._tel_sock.setsockopt(zmq.SNDHWM, 5000)
        self._tel_sock.setsockopt(zmq.LINGER, 0)
        self._tel_sock.bind(TELEMETRY_ADDR)

        # Command PULL socket — receives block/clear/reset commands from backend
        self._cmd_sock = self._zmq_ctx.socket(zmq.PULL)
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 500)
        self._cmd_sock.setsockopt(zmq.LINGER, 0)
        self._cmd_sock.bind(COMMAND_ADDR)

    def _init_state(self) -> None:
        # Switch registry and MAC learning table
        self._datapaths:   dict = {}
        self._mac_to_port: dict = collections.defaultdict(dict)
        FatTreeController._connected_count = 0

        # Per-switch aggregate stats used for telemetry and ML features
        self._switch_agg: dict = collections.defaultdict(lambda: {
            "disp_pakt": 0, "disp_byte": 0, "gfe": 0,
            "g_usip": set(), "rfip": set(),
            "avg_durat": 0.0, "avg_flow_dst": 0,
            "last_reply_ts": None, "disp_interval": 1.0,
        })

        # Tracks switches that have not completed their first stats poll cycle.
        # First poll has duration_sec=0 for all flows — bypass young-flow gate once.
        self._switch_first_poll: set[int] = set()

        # Running packet-in count per switch — used to compute pkt_in rate
        self._pkt_in_count: dict = collections.defaultdict(int)

        # Active port count per switch — from port stats replies
        self._port_counts: dict = collections.defaultdict(int)

        # Previous total packet counts per switch — used to compute delta pps
        self._switch_prev_total: dict[int, int] = {}

        # IPs currently banned — fast check in the throttled packet-in path
        self._banned_ips: set = set()

        # Last switch that saw each src_ip — scopes block rules to one switch
        self._ip_to_dpid: dict[str, int] = {}

        # Previous packet counts per drop rule key — used to compute drop deltas.
        # Key: src_ip for per-IP rules, "__proto__" for protocol-level drop rule.
        self._blocked_prev_pkts: dict[str, int] = {}

        # Cooldown counter per switch — suppresses ML scoring for N intervals
        # after an attack clears to avoid stale flow data triggering false alarms
        self._cooldown_intervals: dict[int, int] = {}
        self._COOLDOWN_INTERVALS = 3

        # Per-switch and per-IP protocol counts — used for RF attack classification
        self._switch_proto: dict = collections.defaultdict(
            lambda: collections.defaultdict(int)
        )
        self._src_proto: dict = collections.defaultdict(
            lambda: collections.defaultdict(int)
        )

        # Fallback protocol cache per src_ip — survives dpid mismatch on re-detection
        self._src_proto_global: dict[str, int] = {}

        # Cached transport ports (tp_src, tp_dst) per src_ip — used as IF features
        self._src_ports: dict[str, tuple[int, int]] = {}

        self._pkt_in_rate: dict = {}
        self._PKT_IN_RATE_LIMIT = 1000

    # ── OpenFlow handshake ─────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        self._datapaths[dp.id] = dp
        FatTreeController._connected_count = len(self._datapaths)
        self.logger.info(
            'Switch CONNECTED  dpid=%016x  (%d/%d switches)',
            dp.id, len(self._datapaths), 9,
        )

        # Notify topology.py of current switch count
        self._push({"type": "switch_count", "connected": len(self._datapaths)})

        # Flush stale rules from previous session — prevents leftover drop rules
        # silently blocking baseline traffic on topology restart
        for pri in (0, 1, 80, 90, 100):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                priority=pri, match=parser.OFPMatch(),
            ))

        # Re-arm first-poll bypass — fresh flows have duration_sec=0 on first poll
        self._switch_first_poll.discard(dp.id)

        # Install table-miss rule at priority=1 — sends unknown flows to controller
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=1,
            match=parser.OFPMatch(), instructions=inst,
        ))

        # Install rate-limit meter on every switch at connect time.
        # Meter ID=1, KBPS band, DROP excess — used by rate_limit action in Phase 1.
        # Pre-installing avoids race condition if rate_limit fires before meter exists.
        self._install_rate_limit_meter(dp, ofp, parser)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnect_handler(self, ev):
        dp   = ev.datapath
        dpid = dp.id
        self._datapaths.pop(dpid, None)
        FatTreeController._connected_count = len(self._datapaths)
        self._switch_agg.pop(dpid, None)
        self._pkt_in_count.pop(dpid, None)
        self._port_counts.pop(dpid, None)
        self.logger.info(
            'Switch DISCONNECTED  dpid=%s  (%d switches remaining)',
            ('%016x' % dpid) if dpid is not None else 'unknown',
            len(self._datapaths),
        )

    # ── PacketIn ───────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = dp.id
        in_port = msg.match["in_port"]

        # Rate limiter — must run first; drops banned IPs in the throttled path
        if self._is_throttled(dpid, dp, ofp, parser, msg, in_port):
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ARP — learn MAC and flood
        if eth.ethertype == 0x0806:
            self._mac_to_port[dpid][eth.src] = in_port
            self._flood(dp, ofp, parser, msg, in_port)
            return

        # Non-IPv4 (LLDP, IPv6, etc.) — learn MAC and flood if unknown dst
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            self._mac_to_port[dpid][eth.src] = in_port
            if eth.dst not in self._mac_to_port[dpid]:
                self._flood(dp, ofp, parser, msg, in_port)
            return

        # IPv4 full processing
        self._handle_ipv4(dp, ofp, parser, dpid, in_port, msg, eth, ip4, pkt)

    def _is_throttled(self, dpid, dp, ofp, parser, msg, in_port) -> bool:
        # Track per-switch packet-in rate — reset counter every 1 second
        now_mono            = time.monotonic()
        _rate_count, _start = self._pkt_in_rate.get(dpid, (0, now_mono))

        if now_mono - _start >= 1.0:
            self._pkt_in_rate[dpid] = (1, now_mono)
            return False

        _rate_count += 1
        self._pkt_in_rate[dpid] = (_rate_count, _start)

        if _rate_count <= self._PKT_IN_RATE_LIMIT:
            return False

        # Over limit — drop banned IPs silently, install forward rule for the rest.
        # Installing a forward rule (instead of flooding) keeps flow_stats flowing
        # so ML can score/re-score. Flooding bypasses the flow table and starves
        # telemetry, creating a feedback loop where IPs become invisible to ML.
        self._pkt_in_count[dpid] += 1
        try:
            _raw_pkt = packet.Packet(msg.data)
            _raw_eth = _raw_pkt.get_protocol(ethernet.ethernet)
            _raw_ip  = _raw_pkt.get_protocol(ipv4.ipv4)
            if _raw_ip:
                if _raw_ip.src in self._banned_ips:
                    return True
                # Non-banned IP under throttle: install forward rule so flow_stats
                # keep flowing and ML can score/re-score.
                if _raw_eth:
                    self._mac_to_port[dpid][_raw_eth.src] = in_port
                    out_port = self._mac_to_port[dpid].get(_raw_eth.dst, ofp.OFPP_FLOOD)
                    if out_port != ofp.OFPP_FLOOD:
                        match   = parser.OFPMatch(eth_type=0x0800, ipv4_src=_raw_ip.src)
                        actions = [parser.OFPActionOutput(out_port)]
                        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        buf_id  = msg.buffer_id if msg.buffer_id != ofp.OFP_NO_BUFFER else ofp.OFP_NO_BUFFER
                        dp.send_msg(parser.OFPFlowMod(
                            datapath=dp, priority=10,
                            idle_timeout=60, hard_timeout=0,
                            buffer_id=buf_id, match=match, instructions=inst,
                        ))
                        if msg.buffer_id != ofp.OFP_NO_BUFFER:
                            return True
                        self._send_packet_out(dp, ofp, parser, msg, in_port, actions)
                        return True
        except Exception:
            pass

        self._flood(dp, ofp, parser, msg, in_port)
        return True

    def _handle_ipv4(self, dp, ofp, parser, dpid, in_port, msg, eth, ip4, pkt) -> None:
        src_ip = ip4.src
        dst_ip = ip4.dst

        # Record which switch last saw this IP — scopes block rules to one switch
        self._ip_to_dpid[src_ip] = dpid

        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        proto         = "TCP" if tcp_pkt else ("ICMP" if icmp_pkt else ("UDP" if udp_pkt else "OTHER"))
        tcp_flags_syn = bool(tcp_pkt and (tcp_pkt.bits & 0x02))
        tcp_flags_ack = bool(tcp_pkt and (tcp_pkt.bits & 0x10))

        self._pkt_in_count[dpid] += 1
        self._update_proto_cache(dpid, src_ip, ip4.proto)
        self._update_port_cache(src_ip, tcp_pkt, udp_pkt)

        self._push({
            "type":          "packet_in",
            "dpid":          dpid,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "proto":         proto,
            "tcp_flags_syn": tcp_flags_syn,
            "tcp_flags_ack": tcp_flags_ack,
            "ts":            time.time(),
        })

        self._mac_to_port[dpid][eth.src] = in_port
        out_port = self._mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        # Install forwarding rule at priority=10 — ipv4_src only match.
        # Priority=10 beats table-miss (1) and stays below block rules (80+).
        if out_port != ofp.OFPP_FLOOD:
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            buf_id = msg.buffer_id if msg.buffer_id != ofp.OFP_NO_BUFFER else ofp.OFP_NO_BUFFER
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=10,
                idle_timeout=60, hard_timeout=0,
                buffer_id=buf_id, match=match, instructions=inst,
            ))
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                return  # buffer already consumed by FlowMod

        self._send_packet_out(dp, ofp, parser, msg, in_port, actions)

    def _update_proto_cache(self, dpid: int, src_ip: str, proto: int) -> None:
        # Track dominant protocol per switch and per IP for RF classification.
        # TCP(6)/UDP(17) take priority over ICMP(1) to avoid warmup pings
        # overwriting the real attack protocol.
        if not proto:
            return
        self._switch_proto[dpid][proto] += 1

        cur = self._src_proto[dpid].get(src_ip, 0)
        if proto in (6, 17) or cur == 0:
            self._src_proto[dpid][src_ip] = proto

        gcur = self._src_proto_global.get(src_ip, 0)
        if proto in (6, 17) or gcur == 0:
            self._src_proto_global[src_ip] = proto

    def _update_port_cache(self, src_ip: str, tcp_pkt, udp_pkt) -> None:
        # Cache transport ports per src_ip — used as IF features (tp_src, tp_dst)
        if tcp_pkt:
            self._src_ports[src_ip] = (tcp_pkt.src_port, tcp_pkt.dst_port)
        elif udp_pkt:
            self._src_ports[src_ip] = (udp_pkt.src_port, udp_pkt.dst_port)

    # ── FlowStats reply ────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        now  = time.time()

        agg      = self._switch_agg[dpid]
        interval = (now - agg["last_reply_ts"]) if agg["last_reply_ts"] else 1.0
        agg["last_reply_ts"] = now
        agg["disp_interval"] = max(interval, 0.001)

        # First poll after connect — all flows have duration_sec=0, bypass gate once
        is_first_poll = dpid not in self._switch_first_poll
        self._switch_first_poll.add(dpid)

        # Reset per-interval switch proto tally
        self._switch_proto[dpid].clear()

        # Tick down post-clear cooldown counter
        if self._cooldown_intervals.get(dpid, 0) > 0:
            self._cooldown_intervals[dpid] -= 1

        total_pkt  = 0
        total_byte = 0
        durations  = []
        dst_ips    = set()
        src_ips    = set()
        _flow_count_per_src: dict[str, int] = collections.defaultdict(int)

        # Compute packet-in rate and reset counter for next interval
        _rate_pkt_in = self._pkt_in_count.get(dpid, 0) / max(interval, 0.001)
        self._pkt_in_count[dpid] = 0

        # Compute switch-wide delta pps from cumulative flow packet counts
        self._update_switch_delta(dpid, agg, body, interval, _rate_pkt_in)

        for stat in body:
            total_pkt  += stat.packet_count
            total_byte += stat.byte_count
            durations.append(stat.duration_sec * 1e6 + stat.duration_nsec / 1000)

            match = stat.match
            if "ipv4_src" in match:
                src_ips.add(match["ipv4_src"])
            if "ipv4_dst" in match:
                dst_ips.add(match["ipv4_dst"])

            # Report drop delta for all drop rules to backend via ZMQ.
            # priority 80/90/100 — per-IP block rules (quarantine/time ban/blackhole)
            # priority 50        — proto drop rule installed by resource guard at CRIT
            self._report_drop_delta(stat, match)

            src_ip = match.get("ipv4_src")
            if not src_ip or src_ip == "0.0.0.0" or src_ip in _SKIP_SRC:
                continue
            if stat.packet_count == 0:
                # Skip zero-packet flows — avoids division blowup in IF features
                continue

            _flow_count_per_src[src_ip] += 1

            # Skip flows younger than 10ms — not yet reliable for ML scoring
            if not is_first_poll:
                if stat.duration_sec == 0 and stat.duration_nsec < 10_000_000:
                    continue

            self._push_flow_stats(dpid, src_ip, stat, match, _flow_count_per_src)

        n_flows = max(len(body), 1)
        agg.update({
            "disp_pakt":    total_pkt,
            "disp_byte":    total_byte,
            "gfe":          n_flows,
            "g_usip":       src_ips,
            "avg_flow_dst": len(dst_ips),
            "avg_durat":    (sum(durations) / n_flows) if durations else 0.0,
            "rate_pkt_in":  _rate_pkt_in,
        })

    def _update_switch_delta(self, dpid, agg, body, interval, rate_pkt_in) -> None:
        # Compute delta pps from cumulative flow packet counts across all flows
        sw_total = sum(s.packet_count for s in body)
        prev     = self._switch_prev_total.get(dpid)
        if prev is None:
            self._switch_prev_total[dpid] = sw_total
            agg["switch_delta_pps"] = 0.0
        else:
            delta = max(sw_total - prev, 0)
            self._switch_prev_total[dpid] = sw_total
            agg["switch_delta_pps"] = max(delta / max(interval, 0.1), rate_pkt_in)

    def _report_drop_delta(self, stat, match) -> None:
        # Send drop delta to backend for per-IP and proto-level drop rules.
        # Key: src_ip for per-IP rules, "__proto__" for protocol-level rule.
        if stat.priority not in _ALL_DROP_PRIORITIES:
            return

        drop_key = (
            match.get("ipv4_src")
            if stat.priority in (80, 90, 100)
            else "__proto__"
        )
        if not drop_key:
            return

        prev  = self._blocked_prev_pkts.get(drop_key, 0)
        delta = max(stat.packet_count - prev, 0)
        self._blocked_prev_pkts[drop_key] = stat.packet_count

        if delta > 0:
            self._push({"type": "dropped_delta", "src_ip": drop_key, "delta": delta})

    def _push_flow_stats(self, dpid, src_ip, stat, match, flow_count_per_src) -> None:
        # Resolve protocol: flow match first, then per-IP cache, then global fallback
        ip_proto = (
            int(match.get("ip_proto", 0))
            or int(self._src_proto[dpid].get(src_ip, 0))
            or int(self._src_proto_global.get(src_ip, 0))
        )

        total_s = max(stat.duration_sec + stat.duration_nsec / 1e9, 1e-9)
        pps     = stat.packet_count / total_s
        bps     = stat.byte_count   / total_s
        ports   = self._src_ports.get(src_ip, (0, 0))

        self._push({
            "type":       "flow_stats",
            "dpid":       dpid,
            "src_ip":     src_ip,
            "flow_stats": {
                "flow_duration_sec":        stat.duration_sec,
                "flow_duration_nsec":       stat.duration_nsec,
                "idle_timeout":             stat.idle_timeout,
                "hard_timeout":             stat.hard_timeout,
                "flags":                    stat.flags,
                "packet_count":             stat.packet_count,
                "byte_count":               stat.byte_count,
                "packet_count_per_second":  pps,
                "packet_count_per_nsecond": pps / 1e9,
                "byte_count_per_second":    bps,
                "byte_count_per_nsecond":   bps / 1e9,
                "ip_proto":                 ip_proto,
                "tp_src":                   ports[0],
                "tp_dst":                   ports[1],
                "flow_count_per_src":       flow_count_per_src[src_ip],
            },
            "switch_stats": self._build_switch_stats(dpid),
        })

    # ── PortStats reply ────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self._port_counts[dpid] = sum(
            1 for p in ev.msg.body if p.rx_packets > 0
        )

    # ── Stats polling loop ─────────────────────────────────────────────────

    def _stats_poll_loop(self) -> None:
        # Poll flow and port stats from every switch every STATS_INTERVAL seconds.
        # Staggered 40ms per switch to avoid burst load on VMware.
        while True:
            hub.sleep(STATS_INTERVAL)
            for dpid, dp in list(self._datapaths.items()):
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
                hub.sleep(0.04)

    def _request_flow_stats(self, dp) -> None:
        dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    def _request_port_stats(self, dp) -> None:
        ofp = dp.ofproto
        dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))

    # ── Command listener ───────────────────────────────────────────────────

    def _command_listener(self) -> None:
        # Listen for ZMQ commands from backend — block/clear/reset/proto_block
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 0)
        while True:
            try:
                raw = self._cmd_sock.recv(zmq.NOBLOCK)
                self._apply_command(json.loads(raw))
            except zmq.Again:
                hub.sleep(0.05)
            except Exception as e:
                self.logger.warning("Command error: %s", e)
                hub.sleep(0.05)

    def _apply_command(self, cmd: dict) -> None:
        action = cmd.get("action")
        src_ip = cmd.get("src_ip")
        ttl    = cmd.get("ttl")

        if action == "reset":
            self._reset_state()
            return

        # Update banned IP set for the throttled fast-path check
        # Only drop actions (block/quarantine/redirect) — rate_limit allows traffic
        # so flow_stats continue and ML can re-score during probation
        if action in ("block", "quarantine", "redirect"):
            self._banned_ips.add(src_ip)
        elif action == "clear":
            self._on_clear(src_ip)

        # Resolve target switches — all switches for mitigation, scoped for clear
        target_dps = self._resolve_target_switches(src_ip, action)

        for dpid, dp in target_dps:
            parser = dp.ofproto_parser
            ofp    = dp.ofproto
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

            if action in _DROP_PRIORITY:
                self._install_drop_rule(dp, ofp, parser, match, action, ttl)
            elif action == "proto_block":
                self._apply_proto_block(dp, ofp, parser, cmd, dpid)
            elif action == "redirect":
                redirect_to = cmd.get("redirect_to", "10.0.0.21")
                self._install_redirect_rule(dp, ofp, parser, match, redirect_to)
            elif action == "clear":
                self._install_clear_rules(dp, ofp, parser, match)

    def _reset_state(self) -> None:
        # Wipe all Ryu in-memory state — called by topology.py on startup.
        # Clears stale bans, MAC table, counters from previous session.
        self._banned_ips.clear()
        self._ip_to_dpid.clear()
        self._mac_to_port.clear()
        self._blocked_prev_pkts.clear()
        self._switch_prev_total.clear()
        self._pkt_in_count.clear()
        self._cooldown_intervals.clear()
        self._switch_proto.clear()
        self._src_proto.clear()
        self._src_proto_global.clear()
        self._src_ports.clear()
        self._pkt_in_rate.clear()
        self._switch_first_poll.clear()
        self.logger.info("*** Ryu state reset — all in-memory state cleared")

    def _on_clear(self, src_ip: str) -> None:
        # Clean up all per-IP state when an IP is unblocked
        self._banned_ips.discard(src_ip)
        self._blocked_prev_pkts.pop(src_ip, None)

        # Remove stale cached protocol so next legit flow is not misclassified
        for dpid_key in list(self._src_proto.keys()):
            self._src_proto[dpid_key].pop(src_ip, None)

        # Reset delta counters to avoid stale pps spike after attack stops
        self._switch_prev_total.clear()

        # Reset packet-in counters on all switches
        for dpid_key in self._pkt_in_count:
            self._pkt_in_count[dpid_key] = 0

        # Start post-clear cooldown on all switches
        for dpid_key in self._datapaths:
            self._cooldown_intervals[dpid_key] = self._COOLDOWN_INTERVALS

    def _resolve_target_switches(self, src_ip: str, action: str = "") -> list:
        # Block/rate_limit/quarantine/redirect — install on ALL switches.
        # Attacker can enter from any edge switch; scoping to one switch
        # leaves other switches unprotected.
        # Clear — scoped to last-seen switch only to avoid unnecessary rule deletion.
        if action in ("block", "rate_limit", "quarantine", "redirect"):
            return list(self._datapaths.items())

        # Clear / fallback — scoped to last-seen switch if known
        target_dpid = self._ip_to_dpid.get(src_ip) if src_ip else None
        if target_dpid is not None and target_dpid in self._datapaths:
            return [(target_dpid, self._datapaths[target_dpid])]
        return list(self._datapaths.items())

    def _install_rate_limit_meter(self, dp, ofp, parser) -> None:
        # Install OpenFlow Meter ID=1 on this switch — DROP excess above RATE_LIMIT_PPS.
        # PKTPS band = packets per second, matches research baseline (1000 pps sim).
        # Replaces existing meter if present — safe to call on reconnect.
        bands = [parser.OFPMeterBandDrop(
            type_=ofp.OFPMBT_DROP,
            rate=RATE_LIMIT_PPS,
            burst_size=RATE_LIMIT_PPS // 10,  # 10% burst allowance
        )]
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp,
            command=ofp.OFPMC_ADD,
            flags=ofp.OFPMF_PKTPS,           # rate unit = packets per second
            meter_id=_RATE_LIMIT_METER_ID,
            bands=bands,
        ))

    def _delete_rate_limit_meter(self, dp, ofp, parser) -> None:
        # Remove meter ID=1 from switch — called on clear to fully release IP.
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp,
            command=ofp.OFPMC_DELETE,
            flags=ofp.OFPMF_PKTPS,
            meter_id=_RATE_LIMIT_METER_ID,
            bands=[],
        ))

    def _install_drop_rule(self, dp, ofp, parser, match, action: str, ttl) -> None:
        # Install mitigation rule for a flagged IP.
        # rate_limit → OpenFlow Meter flow rule (throttle, not full drop).
        # block/quarantine → DROP rule at respective priority.
        #
        # Step 1 — delete stale forward rule (p10), table-miss override (p1),
        #           and any existing rule at the same drop priority.
        # Step 2 — install new rule.
        drop_pri     = _DROP_PRIORITY[action]
        hard_timeout = int(ttl) if (action == "block" and ttl is not None) else 0

        for cmd_type, pri in [
            (ofp.OFPFC_DELETE_STRICT, 10),       # delete stale forward rule
            (ofp.OFPFC_DELETE_STRICT, 85),       # delete stale redirect rule
            (ofp.OFPFC_DELETE_STRICT, 1),        # delete table-miss override
            (ofp.OFPFC_DELETE_STRICT, drop_pri), # delete stale rule at same priority
        ]:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=cmd_type,
                priority=pri,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=match,
            ))

        if action == "rate_limit":
            # Apply meter action — throttles to RATE_LIMIT_PPS, excess dropped by meter.
            # Traffic below limit still reaches server — correct Phase 1 behaviour.
            meter_inst = [
                parser.OFPInstructionMeter(_RATE_LIMIT_METER_ID),
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_NORMAL)],
                ),
            ]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=drop_pri,
                idle_timeout=0, hard_timeout=0,
                match=match, instructions=meter_inst,
            ))
        else:
            # block / quarantine — full DROP
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=drop_pri,
                idle_timeout=0, hard_timeout=hard_timeout,
                match=match, instructions=[],
            ))

    def _apply_proto_block(self, dp, ofp, parser, cmd: dict, dpid: int) -> None:
        # Install or remove a protocol-level drop rule at priority=50.
        # Catches rand-source floods that rotate IPs too fast for per-IP rules.
        # Priority 50 — above table-miss (1), below per-IP block rules (80+).
        proto  = cmd.get("proto")
        remove = cmd.get("remove", False)
        if proto is None:
            return

        proto_match = parser.OFPMatch(eth_type=0x0800, ip_proto=proto)

        if remove:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE_STRICT,
                priority=50,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=proto_match,
            ))
            self.logger.debug("Proto drop removed: nw_proto=%d on dpid=%016x", proto, dpid)
        else:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=50,
                idle_timeout=0, hard_timeout=0,
                match=proto_match, instructions=[],
            ))
            self.logger.debug("Proto drop installed: nw_proto=%d on dpid=%016x", proto, dpid)

    def _install_clear_rules(self, dp, ofp, parser, match) -> None:
        # Remove all drop rules AND the forward rule for this IP.
        # Also deletes priority=10 forward rule so next packet hits packet_in.
        # This forces ML to re-evaluate the IP — critical for probation scoring.
        # Permit at priority=5 lets the released IP forward immediately
        # before the MAC table re-learns naturally (expires in 10s).
        for pri in (100, 90, 85, 80, 10):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE_STRICT,
                priority=pri,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=match,
            ))

        permit_inst = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS,
            [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
        )]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=5,
            idle_timeout=10, hard_timeout=10,
            match=match, instructions=permit_inst,
        ))

    def _install_redirect_rule(self, dp, ofp, parser, match, redirect_to: str) -> None:
        # Install redirect rule: match src_ip, rewrite dst_ip to sinkhole, forward.
        # Priority 85 — above rate_limit (80), below quarantine (90).
        # Delete stale forward rule (p10) and any existing redirect rule (p85).
        for pri in (10, 85):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                priority=pri,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=match,
            ))

        # Actions: set ipv4_dst to sinkhole, output via NORMAL forwarding
        actions = [
            parser.OFPActionSetField(ipv4_dst=redirect_to),
            parser.OFPActionOutput(ofp.OFPP_NORMAL),
        ]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=85,
            idle_timeout=0, hard_timeout=0,
            match=match, instructions=inst,
        ))

    # ── Helpers ────────────────────────────────────────────────────────────

    def _flood(self, dp, ofp, parser, msg, in_port) -> None:
        # Send packet out on all ports — used for ARP and unknown destinations
        buf_id = msg.buffer_id if msg.buffer_id != ofp.OFP_NO_BUFFER else ofp.OFP_NO_BUFFER
        data   = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=buf_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)],
            data=data,
        ))

    def _send_packet_out(self, dp, ofp, parser, msg, in_port, actions) -> None:
        # Send packet out with given actions — used after forwarding rule install
        buf_id = msg.buffer_id if msg.buffer_id != ofp.OFP_NO_BUFFER else ofp.OFP_NO_BUFFER
        data   = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=buf_id,
            in_port=in_port, actions=actions, data=data,
        ))

    def _build_switch_stats(self, dpid: int) -> dict:
        # Build the switch-level stats dict sent with every flow_stats telemetry message
        agg            = self._switch_agg[dpid]
        n              = max(agg["gfe"], 1)
        proto_counts   = self._switch_proto.get(dpid, {})
        dominant_proto = max(proto_counts, key=proto_counts.get) if proto_counts else 0

        return {
            "disp_pakt":     agg["disp_pakt"],
            "disp_byte":     agg["disp_byte"],
            "mean_pkt":      agg["disp_pakt"] / n,
            "mean_byte":     agg["disp_byte"] / n,
            "avg_durat":     agg["avg_durat"],
            "avg_flow_dst":  agg["avg_flow_dst"],
            "rate_pkt_in":   agg.get("rate_pkt_in", 0),
            "disp_interval": agg["disp_interval"],
            "gfe":           agg["gfe"],
            "g_usip":        len(agg["g_usip"]),
            "rfip":          self._count_rfip(dpid),
            "gsp":           self._port_counts.get(dpid, 0),
            "ip_proto":      dominant_proto,
        }

    def _count_rfip(self, dpid: int) -> int:
        # Estimate number of remote-facing IPs — used as a switch-level ML feature
        agg    = self._switch_agg[dpid]
        sample = next(iter(agg["g_usip"]), None)
        if not sample:
            return 0
        try:
            ipaddress.ip_network(f"{sample}/24", strict=False)
        except ValueError:
            return 0
        return max(0, agg["avg_flow_dst"] - 1)

    def _push(self, msg: dict) -> None:
        # Non-blocking ZMQ push — drops silently if send buffer is full
        try:
            self._tel_sock.send_json(msg, zmq.NOBLOCK)
        except zmq.Again:
            pass