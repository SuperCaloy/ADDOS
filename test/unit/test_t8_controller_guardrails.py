"""T8: controller disconnect/overload guardrails (plan BFA-P5a/P5b/P5c, M1, M4).

Pins the behaviors agreed in notes/tasks/blocking-flow-audit-and-fix-plan-2026-08-26.md:
- P5c: a stale DEAD event for an old connection must not evict a newer
  datapath registration for the same dpid.
- M4: _handle_ipv4 must early-return for banned sources (no forward, no
  telemetry, no rule install).
- P5a: over-limit packet-ins must not serialize one FlowMod per packet;
  installs are deduped per (switch, src), capped per second, and the dedup
  state is invalidated at every rule delete site.
- M1: meter install on connect is delete-then-add, and OFP error messages
  are logged rate-limited instead of silently dropped.

The controller class is instantiated via __new__ (no Ryu app manager) and
collaborators are fakes; only synchronous logic is exercised.
"""
import collections
import logging
import struct
import time
from types import SimpleNamespace

import pytest

from controller.ryu_controller import FatTreeController


# ── fakes ────────────────────────────────────────────────────────────────

class FakeOfp:
    OFPFC_DELETE = "DELETE"
    OFPFC_DELETE_STRICT = "DELETE_STRICT"
    OFPP_ANY = "ANY"
    OFPG_ANY = "ANY_GROUP"
    OFPP_NORMAL = "NORMAL"
    OFPP_CONTROLLER = "CONTROLLER"
    OFPP_FLOOD = "FLOOD"
    OFPCML_NO_BUFFER = 0xFFFF
    OFP_NO_BUFFER = 0xFFFFFFFF
    OFPMC_ADD = "ADD"
    OFPMC_DELETE = "DELETE"
    OFPMF_PKTPS = 1 << 0
    OFPMBT_DROP = 1
    OFPIT_APPLY_ACTIONS = 0


class FakeParser:
    """Builds message objects; does NOT record them. Recording happens
    exclusively in FakeDP.send_msg so every send is counted exactly once."""

    def __init__(self, sink):
        self._sink = sink

    def OFPMatch(self, **kw):
        return dict(kw)

    def OFPFlowMod(self, **kw):
        obj = SimpleNamespace(**kw)
        obj.msg_type = "flow"
        return obj

    def OFPMeterMod(self, **kw):
        obj = SimpleNamespace(**kw)
        obj.msg_type = "meter"
        return obj

    def OFPMeterBandDrop(self, **kw):
        return SimpleNamespace(**kw)

    def OFPActionOutput(self, port, max_len=0):
        return ("out", port)

    def OFPActionSetField(self, **kw):
        return ("setfield", kw)

    def OFPInstructionActions(self, itype, actions):
        return ("inst_actions", itype, actions)

    def OFPInstructionMeter(self, meter_id):
        return ("inst_meter", meter_id)

    def OFPPacketOut(self, **kw):
        obj = SimpleNamespace(**kw)
        obj.msg_type = "packet_out"
        return obj


class FakeDP:
    def __init__(self, dpid=1):
        self.id = dpid
        self.sent = []
        self.ofproto = FakeOfp()
        self.ofproto_parser = FakeParser(self.sent)

    def send_msg(self, msg):
        self.sent.append(msg)


def frame(src_ip="10.0.0.66", dst_ip="10.0.0.20", ethertype=0x0800):
    """Minimal Eth+IPv4+TCP bytes the ryu parser accepts."""
    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", ethertype)
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp


def make_controller():
    c = FatTreeController.__new__(FatTreeController)
    c.logger = logging.getLogger("t8")
    c._datapaths = {}
    c._switch_agg = collections.defaultdict(dict)
    c._pkt_in_count = collections.defaultdict(int)
    c._port_counts = {}
    c._banned_ips = set()
    c._pkt_in_rate = {}
    c._PKT_IN_RATE_LIMIT = 1000
    c._mac_to_port = collections.defaultdict(dict)
    c._switch_prev_total = {}
    c._switch_proto = collections.defaultdict(lambda: collections.defaultdict(int))
    c._src_proto = collections.defaultdict(dict)
    c._src_proto_global = {}
    c._src_ports = {}
    c._blocked_prev_pkts = collections.defaultdict(int)
    c._cooldown_intervals = {}
    c._ip_to_dpid = {}
    c._recent_installs = {}
    c._install_budget = {}
    c._last_err_log_ts = 0.0
    c._COOLDOWN_INTERVALS = 3
    c._push = lambda msg: None
    c._build_switch_stats = lambda dpid: {}
    return c


def over_limit(controller, dpid=1):
    controller._pkt_in_rate[dpid] = (controller._PKT_IN_RATE_LIMIT, time.monotonic() - 0.5)


def throttle_call(controller, dp, src_ip, in_port=1):
    msg = SimpleNamespace(data=frame(src_ip), buffer_id=FakeOfp.OFP_NO_BUFFER,
                          match={"in_port": in_port})
    return controller._is_throttled(dp.id, dp, dp.ofproto, dp.ofproto_parser,
                                    msg, in_port)


def flowmods(dp):
    return [m for m in dp.sent if getattr(m, "msg_type", "") == "flow"]


def installs(dp):
    """Only p10 forward-rule installs: excludes DELETE_STRICTs (command attr),
    the p5 post-clear permit, and mitigation rules."""
    return [m for m in dp.sent
            if getattr(m, "msg_type", "") == "flow"
            and not hasattr(m, "command")
            and getattr(m, "priority", None) == 10]


# ── P5c: stale disconnect must not evict a newer datapath ───────────────

def test_stale_disconnect_keeps_new_datapath():
    c = make_controller()
    old_dp, new_dp = FakeDP(7), FakeDP(7)
    c._datapaths[7] = new_dp
    c._switch_agg[7] = {"last_reply_ts": time.time()}
    c._pkt_in_count[7] = 42
    c._port_counts[7] = 4

    c.switch_disconnect_handler(SimpleNamespace(datapath=old_dp))

    assert c._datapaths.get(7) is new_dp
    assert c._pkt_in_count[7] == 42
    assert 7 in c._port_counts


def test_own_disconnect_still_pops_state():
    c = make_controller()
    dp = FakeDP(7)
    c._datapaths[7] = dp
    c._pkt_in_count[7] = 42

    c.switch_disconnect_handler(SimpleNamespace(datapath=dp))

    assert 7 not in c._datapaths
    assert 7 not in c._pkt_in_count


# ── M4: banned sources are dropped before forwarding in _handle_ipv4 ────

def test_handle_ipv4_drops_banned_src_early():
    c = make_controller()
    c._banned_ips.add("10.0.0.66")
    dp = FakeDP(1)
    eth = SimpleNamespace(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    ip4 = SimpleNamespace(src="10.0.0.66", dst="10.0.0.20", proto=6)

    c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1, None, eth, ip4, None)

    assert dp.sent == []
    assert "aa:bb:cc:dd:ee:ff" not in c._mac_to_port[1]


def test_handle_ipv4_still_forwards_unbanned_src():
    c = make_controller()
    dp = FakeDP(1)
    eth = SimpleNamespace(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    ip4 = SimpleNamespace(src="10.0.0.30", dst="10.0.0.20", proto=6)
    pkt = SimpleNamespace(get_protocol=lambda proto: None)

    c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1,
                   SimpleNamespace(data=frame("10.0.0.30"),
                                   buffer_id=FakeOfp.OFP_NO_BUFFER,
                                   match={"in_port": 1}),
                   eth, ip4, pkt)

    assert len(installs(dp)) == 1


# ── P5a: install dedup + cap in the over-limit path ─────────────────────

def test_throttle_dedup_skips_reinstall_within_ttl():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)

    assert throttle_call(c, dp, "10.0.0.66") is True
    first = len(installs(dp))
    assert first == 1

    assert throttle_call(c, dp, "10.0.0.66") is True
    assert len(installs(dp)) == first


def test_throttle_install_cap_bounds_unique_installs():
    c = make_controller()
    c._INSTALL_CAP_PER_SEC = 2
    dp = FakeDP(1)
    over_limit(c)

    for i in range(5):
        assert throttle_call(c, dp, f"10.0.1.{i}") is True

    assert len(installs(dp)) == 2


def test_below_limit_path_unaffected_by_cap():
    c = make_controller()
    c._INSTALL_CAP_PER_SEC = 1
    dp = FakeDP(1)

    for i in range(3):
        c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1,
                       SimpleNamespace(data=frame(f"10.0.2.{i}"),
                                       buffer_id=FakeOfp.OFP_NO_BUFFER,
                                       match={"in_port": 1}),
                       SimpleNamespace(src="aa:bb:cc:dd:ee:0%d" % i,
                                       dst="11:22:33:44:55:66"),
                       SimpleNamespace(src=f"10.0.2.{i}", dst="10.0.0.20",
                                       proto=6),
                       SimpleNamespace(get_protocol=lambda proto: None))

    assert len(installs(dp)) == 3


def test_block_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    c._banned_ips.add("10.0.0.66")
    c._apply_command({"action": "block", "src_ip": "10.0.0.66", "ttl": 30})

    # Rule deleted by the block install: a later packet must reinstall,
    # never be swallowed by a stale dedup entry.
    c._banned_ips.discard("10.0.0.66")
    c._datapaths[1] = dp
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def test_clear_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")

    c._datapaths[1] = dp
    c._apply_command({"action": "clear", "src_ip": "10.0.0.66"})

    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def test_epoch_delete_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    stat = SimpleNamespace(packet_count=5, byte_count=500, duration_sec=601,
                           duration_nsec=0, priority=10,
                           match={"ipv4_src": "10.0.0.66"}, idle_timeout=60,
                           hard_timeout=0, flags=0)
    c._switch_agg[1].update({"last_reply_ts": time.time() - 1.0,
                             "disp_interval": 1.0})
    c.flow_stats_reply_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp, body=[stat])))

    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def test_stats_reply_refreshes_dedup_for_live_rule():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    # A live p10 entry seen in stats proves the rule exists: dedup must
    # stay fresh even past the install TTL.
    stat = SimpleNamespace(packet_count=300, byte_count=30000, duration_sec=70,
                           duration_nsec=0, priority=10,
                           match={"ipv4_src": "10.0.0.66"}, idle_timeout=60,
                           hard_timeout=0, flags=0)
    c._switch_agg[1].update({"last_reply_ts": time.time() - 1.0,
                             "disp_interval": 1.0})
    c.flow_stats_reply_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp, body=[stat])))

    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1


# ── M1: meter install hygiene + error visibility ────────────────────────

def test_meter_install_deletes_before_add():
    c = make_controller()
    dp = FakeDP(1)

    c._install_rate_limit_meter(dp, dp.ofproto, dp.ofproto_parser)

    meters = [m for m in dp.sent if getattr(m, "msg_type", "") == "meter"]
    assert len(meters) == 2
    assert meters[0].command == FakeOfp.OFPMC_DELETE
    assert meters[1].command == FakeOfp.OFPMC_ADD


def test_error_msg_handler_exists_and_is_rate_limited():
    c = make_controller()
    records = []
    c.logger = logging.getLogger("t8.err")
    c.logger.addHandler(_ListHandler(records))
    dp = FakeDP(1)
    ev = SimpleNamespace(msg=SimpleNamespace(type=1, code=3, datapath=dp,
                                             data=b"oops"))

    c.error_msg_handler(ev)
    c.error_msg_handler(ev)  # inside the suppression window
    assert len(records) == 1

    c._last_err_log_ts -= 6.0  # window elapsed
    c.error_msg_handler(ev)
    assert len(records) == 2


class _ListHandler(logging.Handler):
    def __init__(self, sink):
        super().__init__()
        self._sink = sink

    def emit(self, record):
        self._sink.append(record)
