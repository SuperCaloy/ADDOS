# eventlet must be patched first
import eventlet
eventlet.monkey_patch()

import json
import time
import collections

import zmq
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp, udp
from ryu.lib import hub

TELEMETRY_ADDR = "tcp://127.0.0.1:5555"
COMMAND_ADDR   = "tcp://127.0.0.1:5556"
STATS_INTERVAL = 1.0

# Skip flows originating from server/sinkhole (reply traffic)
_SKIP_SRC = {"10.0.0.20", "10.0.0.21"}


class FatTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ZMQ sockets: telemetry PUSH, command PULL
        self._zmq_ctx  = zmq.Context()

        self._tel_sock = self._zmq_ctx.socket(zmq.PUSH)
        self._tel_sock.setsockopt(zmq.SNDHWM, 5000)
        self._tel_sock.setsockopt(zmq.LINGER, 0)
        self._tel_sock.bind(TELEMETRY_ADDR)

        self._cmd_sock = self._zmq_ctx.socket(zmq.PULL)
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 500)
        self._cmd_sock.setsockopt(zmq.LINGER, 0)
        self._cmd_sock.bind(COMMAND_ADDR)

        # Switch registry and MAC table
        self._datapaths: dict   = {}
        self._mac_to_port: dict = collections.defaultdict(dict)
        FatTreeController._connected_count = 0

        # Per-switch aggregate stats for telemetry
        self._switch_prev_total: dict[int, tuple] = {}
        self._switch_agg: dict = collections.defaultdict(lambda: {
            "disp_pakt": 0, "disp_byte": 0, "gfe": 0,
            "g_usip": set(), "rfip": set(),
            "avg_durat": 0.0, "avg_flow_dst": 0,
            "last_reply_ts": None, "disp_interval": 1.0,
        })

        # Track which switches have completed their first stats poll cycle.
        # First poll always has duration_sec=0 for all flows — skip the young-flow
        # gate on first poll so fresh flows after restart are not all dropped silently.
        self._switch_first_poll: set[int] = set()

        self._pkt_in_count: dict = collections.defaultdict(int)
        self._port_counts:  dict = collections.defaultdict(int)

        # Banned IPs — also checked in throttled fast-path
        self._banned_ips: set = set()

        # Track which dpid last saw each src_ip — used to scope block rules
        # to only the attacker's switch, not all switches
        self._ip_to_dpid: dict[str, int] = {}

        # Track cumulative dropped packets per blocked IP for real drop counter
        self._blocked_prev_pkts: dict[str, int] = {}

        # Cooldown: suppress flood detection for N intervals after attack cleared
        self._cooldown_intervals: dict[int, int] = {}
        self._COOLDOWN_INTERVALS = 3

        # Per-switch and per-IP protocol tracking for RF classification
        self._switch_proto: dict = collections.defaultdict(lambda: collections.defaultdict(int))
        self._src_proto:    dict = collections.defaultdict(lambda: collections.defaultdict(int))

        # Cache tp_src, tp_dst per src_ip for IF features
        self._src_ports: dict[str, tuple[int, int]] = {}
        self._src_proto_global: dict[str, int] = {}  # fallback: ip -> proto across all dpids

        # PacketIn rate limiter — prevents OVS overload under rand-source floods
        self._pkt_in_rate: dict = {}
        self._PKT_IN_RATE_LIMIT = 150

        hub.spawn(self._stats_poll_loop)
        hub.spawn(self._command_listener)

    # ------------------------------------------------------------------
    # OpenFlow handshake
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        self._datapaths[dp.id] = dp
        FatTreeController._connected_count = len(self._datapaths)
        self.logger.info(
            '✔ Switch CONNECTED  dpid=%016x  (%d/%d switches)',
            dp.id, len(self._datapaths), 9
        )

        # Push switch count so topology.py can poll without Ryu REST app
        self._push({
            "type":      "switch_count",
            "connected": len(self._datapaths),
        })

        # Flush ALL stale rules on reconnect — clears warmup floods AND
        # any leftover block rules (80,90,100) from previous attack session.
        # Without flushing 80/90/100, old drop rules survive mn -c and
        # silently drop baseline traffic on every topology restart.
        for pri in (0, 1, 80, 90, 100):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                priority=pri, match=parser.OFPMatch(),
            ))

        # Mark this switch as needing first-poll bypass — fresh flows
        # all have duration_sec=0 on first poll so they'd all be skipped
        # without this flag. Cleared automatically after first poll cycle.
        self._switch_first_poll.discard(dp.id)

        # Table-miss at priority=1 so it always overrides any leftover priority=0 rules
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=1, match=parser.OFPMatch(), instructions=inst))

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
            '✘ Switch DISCONNECTED  dpid=%s  (%d switches remaining)',
            ('%016x' % dpid) if dpid is not None else 'unknown',
            len(self._datapaths)
        )

    # ------------------------------------------------------------------
    # PacketIn
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = dp.id
        in_port = msg.match["in_port"]

        # Rate limiter — must run first; drops banned IPs in throttled path
        now_mono    = time.monotonic()
        _rate_entry = self._pkt_in_rate.get(dpid, (0, now_mono))
        _rate_count, _rate_start = _rate_entry
        if now_mono - _rate_start >= 1.0:
            self._pkt_in_rate[dpid] = (1, now_mono)
            _throttled = False
        else:
            _rate_count += 1
            self._pkt_in_rate[dpid] = (_rate_count, _rate_start)
            _throttled = (_rate_count > self._PKT_IN_RATE_LIMIT)

        if _throttled:
            self._pkt_in_count[dpid] += 1
            try:
                _raw_pkt = packet.Packet(msg.data)
                _raw_ip  = _raw_pkt.get_protocol(ipv4.ipv4)
                if _raw_ip and _raw_ip.src in self._banned_ips:
                    return  # drop banned IP silently
            except Exception:
                pass

            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=None)
            else:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        # Full processing path
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ARP — flood and return
        if eth.ethertype == 0x0806:
            self._mac_to_port[dpid][eth.src] = in_port
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=None)
            else:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        # Non-IPv4 (LLDP, IPv6 etc.)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            self._mac_to_port[dpid][eth.src] = in_port
            if eth.dst not in self._mac_to_port[dpid]:
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    out = parser.OFPPacketOut(
                        datapath=dp, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=None)
                else:
                    out = parser.OFPPacketOut(
                        datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)
            return

        # IPv4 full processing
        src_ip = ip4.src
        dst_ip = ip4.dst

        # Record which switch last saw this src_ip — scopes block rules
        # to this switch only instead of broadcasting to all switches
        self._ip_to_dpid[src_ip] = dpid

        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        proto         = "TCP" if tcp_pkt else ("ICMP" if icmp_pkt else ("UDP" if udp_pkt else "OTHER"))
        tcp_flags_syn = bool(tcp_pkt and (tcp_pkt.bits & 0x02))
        tcp_flags_ack = bool(tcp_pkt and (tcp_pkt.bits & 0x10))

        self._pkt_in_count[dpid] += 1

        # Track per-IP protocol for RF classification
        if ip4.proto:
            self._switch_proto[dpid][ip4.proto] += 1
            # TCP(6)/UDP(17) take priority over ICMP(1) — prevents warmup ping overwriting real proto
            cur = self._src_proto[dpid].get(src_ip, 0)
            if ip4.proto in (6, 17) or cur == 0:
                self._src_proto[dpid][src_ip] = ip4.proto
            # global fallback — survives dpid mismatch
            gcur = self._src_proto_global.get(src_ip, 0)
            if ip4.proto in (6, 17) or gcur == 0:
                self._src_proto_global[src_ip] = ip4.proto

        # Cache tp_src, tp_dst per src_ip for IF features
        _tp_src = _tp_dst = 0
        if tcp_pkt:
            _tp_src, _tp_dst = tcp_pkt.src_port, tcp_pkt.dst_port
        elif udp_pkt:
            _tp_src, _tp_dst = udp_pkt.src_port, udp_pkt.dst_port
        if _tp_src or _tp_dst:
            self._src_ports[src_ip] = (_tp_src, _tp_dst)

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

        if eth.dst in self._mac_to_port[dpid]:
            out_port = self._mac_to_port[dpid][eth.dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding rule — ipv4_src only match, priority=10.
        # Why ipv4_src only: old match (in_port+ip_proto+eth_dst) caused rule
        # misses when MAC aged -> n_packets=0, and same-port loops on edge switches.
        # Why priority=10: at priority=1 forwarding tied with table-miss wildcard.
        # OVS hit table-miss first (installed earlier) so forwarding never fired.
        # priority=10 beats table-miss (1), stays below block rules (80/90/100).
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
            )
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=10,
                    idle_timeout=60, hard_timeout=0,
                    buffer_id=msg.buffer_id,
                    match=match, instructions=inst)
                dp.send_msg(mod)
                return
            else:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=10,
                    idle_timeout=60, hard_timeout=0,
                    match=match, instructions=inst)
                dp.send_msg(mod)

        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=None)
        else:
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    # ------------------------------------------------------------------
    # FlowStats reply
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid  = ev.msg.datapath.id
        body  = ev.msg.body
        now   = time.time()

        agg      = self._switch_agg[dpid]
        prev_ts  = agg["last_reply_ts"]
        interval = (now - prev_ts) if prev_ts else 1.0
        agg["last_reply_ts"] = now
        agg["disp_interval"] = max(interval, 0.001)

        # First poll cycle for this switch — all flows have duration_sec=0
        # because they were just installed. Bypass the young-flow gate this
        # cycle only so fresh flows after restart reach the ML pipeline.
        # After this poll, mark the switch as seen so normal gating resumes.
        _is_first_poll = dpid not in self._switch_first_poll
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
        # Count flows per src_ip for flow_count_per_src feature
        _flow_count_per_src: dict[str, int] = collections.defaultdict(int)

        # Compute pkt_in rate then reset counter
        _rate_pkt_in_now = self._pkt_in_count.get(dpid, 0) / max(interval, 0.001)
        self._pkt_in_count[dpid] = 0

        # Compute switch-wide delta pps
        _sw_total_now = sum(s.packet_count for s in body)
        _prev_entry   = self._switch_prev_total.get(dpid)
        if _prev_entry is None:
            self._switch_prev_total[dpid] = _sw_total_now
            agg["switch_delta_pps"] = 0.0
        else:
            _sw_delta = max(_sw_total_now - _prev_entry, 0)
            self._switch_prev_total[dpid] = _sw_total_now
            _flow_based_delta_pps = _sw_delta / max(interval, 0.1)
            agg["switch_delta_pps"] = max(_flow_based_delta_pps, _rate_pkt_in_now)

        for stat in body:
            total_pkt  += stat.packet_count
            total_byte += stat.byte_count
            dur_us = stat.duration_sec * 1e6 + stat.duration_nsec / 1000
            durations.append(dur_us)

            match = stat.match
            if "ipv4_src" in match:
                src_ips.add(match["ipv4_src"])
            if "ipv4_dst" in match:
                dst_ips.add(match["ipv4_dst"])

            # Send real drop delta for blocked flow entries (priority 80/90/100)
            if stat.priority in (80, 90, 100):
                _blocked_src = match.get("ipv4_src")
                if _blocked_src:
                    _prev_pkts = self._blocked_prev_pkts.get(_blocked_src, 0)
                    _delta     = max(stat.packet_count - _prev_pkts, 0)
                    self._blocked_prev_pkts[_blocked_src] = stat.packet_count
                    if _delta > 0:
                        self._push({
                            "type":   "dropped_delta",
                            "src_ip": _blocked_src,
                            "delta":  _delta,
                        })

            _total_s = stat.duration_sec + stat.duration_nsec / 1e9
            _total_s = max(_total_s, 1e-9)
            pps  = stat.packet_count / _total_s
            bps  = stat.byte_count   / _total_s
            ppns = pps / 1e9
            bpns = bps / 1e9

            src_ip = match.get("ipv4_src")
            if not src_ip or src_ip == "0.0.0.0":
                continue
            if src_ip in _SKIP_SRC:  # skip server/sinkhole reply traffic
                continue
            _flow_count_per_src[src_ip] += 1
            if stat.packet_count == 0:
                # no traffic yet -- avoids eps-division blowup in
                # duration_pkt_ratio (IF feature), always-anomaly bug
                continue

            # is_flood_switch gate removed.
            # It submitted ALL hosts on a flooded switch to the worker queue,
            # causing innocent hosts on the same switch to be scored or
            # timeout-blocked even though IF never confirmed them as attackers.
            # IF scores every host independently per-poll -- it does not need
            # a switch-wide flood gate to detect the real attacker.
            # switch_delta_pps still computed in agg for display/logging only.
            _cooldown_left = self._cooldown_intervals.get(dpid, 0)

            if _is_first_poll:
                # First poll after restart -- bypass young-flow gate so baseline
                # traffic is not silently dropped on topology restart.
                pass
            else:
                # Normal mode -- skip flows younger than 10ms (not yet reliable)
                if stat.duration_sec == 0 and stat.duration_nsec < 10_000_000:
                    continue

            # Resolve protocol: flow match first, then per-IP cache
            _flow_ip_proto = int(match.get("ip_proto", 0))
            if not _flow_ip_proto:
                _flow_ip_proto = int(self._src_proto[dpid].get(src_ip, 0))
            if not _flow_ip_proto:
                _flow_ip_proto = int(self._src_proto_global.get(src_ip, 0))

            _ports = self._src_ports.get(src_ip, (0, 0))
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
                    "packet_count_per_nsecond": ppns,
                    "byte_count_per_second":    bps,
                    "byte_count_per_nsecond":   bpns,
                    "ip_proto":                 _flow_ip_proto,
                    "tp_src":                   _ports[0],
                    "tp_dst":                   _ports[1],
                    "flow_count_per_src":       _flow_count_per_src[src_ip],
                },
                "switch_stats": self._build_switch_stats(dpid),
            })

        n_flows = max(len(body), 1)
        agg["disp_pakt"]    = total_pkt
        agg["disp_byte"]    = total_byte
        agg["gfe"]          = n_flows
        agg["g_usip"]       = src_ips
        agg["avg_flow_dst"] = len(dst_ips)
        agg["avg_durat"]    = (sum(durations) / n_flows) if durations else 0.0
        agg["rate_pkt_in"]  = _rate_pkt_in_now

    # ------------------------------------------------------------------
    # PortStats reply
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid   = ev.msg.datapath.id
        active = sum(1 for p in ev.msg.body if p.rx_packets > 0)
        self._port_counts[dpid] = active

    # ------------------------------------------------------------------
    # Stats polling loop
    # ------------------------------------------------------------------

    def _stats_poll_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            for dpid, dp in list(self._datapaths.items()):
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
                hub.sleep(0.04)  # stagger per switch to avoid VMware burst

    def _request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowStatsRequest(dp))

    def _request_port_stats(self, dp):
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))

    # ------------------------------------------------------------------
    # Command listener
    # ------------------------------------------------------------------

    def _command_listener(self):
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 0)
        while True:
            try:
                raw = self._cmd_sock.recv(zmq.NOBLOCK)
                cmd = json.loads(raw)
                self._apply_command(cmd)
            except zmq.Again:
                hub.sleep(0.05)
            except Exception as e:
                self.logger.warning("Command error: %s", e)
                hub.sleep(0.05)

    def _apply_command(self, cmd: dict):
        action = cmd.get("action")
        src_ip = cmd.get("src_ip")
        ttl    = cmd.get("ttl")

        # ── reset: wipe ALL Ryu in-memory state ───────────────────────────────
        # Called by topology.py on startup via ZMQ before baseline starts.
        # Clears stale banned_ips, ip->dpid map, mac table, counters from
        # previous session so old block rules don't affect new baseline traffic.
        if action == "reset":
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
            # Re-arm first-poll bypass so fresh flows pass young-flow gate on restart
            self._switch_first_poll.clear()
            self.logger.info("*** Ryu state reset — all in-memory state cleared")
            return

        # Update banned IP set for throttled fast-path
        if action in ("block", "rate_limit", "quarantine"):
            self._banned_ips.add(src_ip)
        elif action == "clear":
            self._banned_ips.discard(src_ip)
            # Reset drop counter for this IP
            self._blocked_prev_pkts.pop(src_ip, None)
            # Clear stale cached protocol so next legit flow isn't misclassified
            for dpid_key in list(self._src_proto.keys()):
                self._src_proto[dpid_key].pop(src_ip, None)
            # Reset switch delta counters to avoid stale pps spike after attack stops
            for dpid_key in list(self._switch_prev_total.keys()):
                self._switch_prev_total.pop(dpid_key, None)
            # Reset pkt_in counters
            for dpid_key in list(self._pkt_in_count.keys()):
                self._pkt_in_count[dpid_key] = 0
            # Start cooldown on all switches
            for dpid_key in list(self._datapaths.keys()):
                self._cooldown_intervals[dpid_key] = self._COOLDOWN_INTERVALS

        # ── Scope rules to attacker's switch only ─────────────────────────────
        # _ip_to_dpid is updated on every packet-in — tells us which switch
        # the src_ip was last seen on. Install block/clear only on that switch.
        # If dpid unknown (e.g. clear after restart), broadcast to all switches
        # so stale rules are guaranteed to be removed everywhere.
        target_dpid = self._ip_to_dpid.get(src_ip) if src_ip else None
        if target_dpid is not None and target_dpid in self._datapaths:
            # Known switch — install on this switch only
            target_dps = [(target_dpid, self._datapaths[target_dpid])]
        else:
            # Unknown switch — broadcast to all (safe fallback for clear ops)
            target_dps = list(self._datapaths.items())

        for dpid, dp in target_dps:
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            # Base match: src IP only — scoped to this attacker's IP address
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

            # Map action → drop priority
            _DROP_PRI = {"block": 100, "quarantine": 90, "rate_limit": 80}

            if action in _DROP_PRI:
                drop_pri = _DROP_PRI[action]

                # Step 1: delete existing forwarding rule (priority=1) for this IP
                # STRICT delete — only removes this IP's entry, not other hosts
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp,
                    command=ofp.OFPFC_DELETE_STRICT,
                    priority=1,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    match=match,
                ))

                # Step 2: delete any stale drop rule at this priority for this IP
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp,
                    command=ofp.OFPFC_DELETE_STRICT,
                    priority=drop_pri,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    match=match,
                ))

                # Step 3: install drop rule — hard_timeout only for timed blocks
                hard_timeout = int(ttl) if (action == "block" and ttl is not None) else 0
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, priority=drop_pri,
                    idle_timeout=0, hard_timeout=hard_timeout,
                    match=match, instructions=[]))

            elif action == "clear":
                # Delete drop rules at all block priorities — STRICT so only this IP
                for _pri in (100, 90, 80):
                    dp.send_msg(parser.OFPFlowMod(
                        datapath=dp,
                        command=ofp.OFPFC_DELETE_STRICT,
                        priority=_pri,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                        match=match,
                    ))

                # Push explicit permit rule so released IP forwards immediately
                # Priority 5 — above table-miss (1), below any future block (80+)
                # TTL 10s — expires after MAC table re-learns naturally
                permit_inst = [parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                )]
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, priority=5,
                    idle_timeout=10, hard_timeout=10,
                    match=match, instructions=permit_inst))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_switch_stats(self, dpid: int) -> dict:
        agg = self._switch_agg[dpid]
        n   = max(agg["gfe"], 1)

        # Pick dominant protocol this interval
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
        import ipaddress
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
        try:
            self._tel_sock.send_json(msg, zmq.NOBLOCK)
        except zmq.Again:
            pass