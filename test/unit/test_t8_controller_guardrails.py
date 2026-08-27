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

Importing controller.ryu_controller executes eventlet.monkey_patch(), which
poisons the pytest process for later backend tests (threading primitives are
swapped mid-run). Each scenario therefore runs in a dedicated subprocess via
run_scenario(); the pytest side asserts on the JSON verdicts.
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent

WORKER = r'''
import collections
import json
import logging
import struct
import sys
import time
import traceback
from types import SimpleNamespace

sys.path.insert(0, {repo_root!r})

from controller.ryu_controller import FatTreeController


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
    c._datapaths = {{}}
    c._switch_agg = collections.defaultdict(dict)
    c._pkt_in_count = collections.defaultdict(int)
    c._port_counts = {{}}
    c._banned_ips = set()
    c._pkt_in_rate = {{}}
    c._PKT_IN_RATE_LIMIT = 1000
    c._mac_to_port = collections.defaultdict(dict)
    c._switch_prev_total = {{}}
    c._switch_proto = collections.defaultdict(
        lambda: collections.defaultdict(int))
    c._src_proto = collections.defaultdict(dict)
    c._src_proto_global = {{}}
    c._src_ports = {{}}
    c._blocked_prev_pkts = collections.defaultdict(int)
    c._cooldown_intervals = {{}}
    c._ip_to_dpid = {{}}
    c._recent_installs = {{}}
    c._install_budget = {{}}
    c._last_err_log_ts = 0.0
    c._COOLDOWN_INTERVALS = 3
    c._push = lambda msg: None
    c._build_switch_stats = lambda dpid: {{}}
    return c


def over_limit(controller, dpid=1):
    controller._pkt_in_rate[dpid] = (
        controller._PKT_IN_RATE_LIMIT, time.monotonic() - 0.5)


def throttle_call(controller, dp, src_ip, in_port=1):
    msg = SimpleNamespace(data=frame(src_ip),
                          buffer_id=FakeOfp.OFP_NO_BUFFER,
                          match={{"in_port": in_port}})
    return controller._is_throttled(dp.id, dp, dp.ofproto,
                                    dp.ofproto_parser, msg, in_port)


def installs(dp):
    """Only p10 forward-rule installs: excludes DELETE_STRICTs (command
    attr), the p5 post-clear permit, and mitigation rules."""
    return [m for m in dp.sent
            if getattr(m, "msg_type", "") == "flow"
            and not hasattr(m, "command")
            and getattr(m, "priority", None) == 10]


class _ListHandler(logging.Handler):
    def __init__(self, sink):
        super().__init__()
        self._sink = sink

    def emit(self, record):
        self._sink.append(record)


# ── scenarios ────────────────────────────────────────────────────────────

def scenario_stale_disconnect_keeps_new_datapath():
    c = make_controller()
    old_dp, new_dp = FakeDP(7), FakeDP(7)
    c._datapaths[7] = new_dp
    c._switch_agg[7] = {{"last_reply_ts": time.time()}}
    c._pkt_in_count[7] = 42
    c._port_counts[7] = 4

    c.switch_disconnect_handler(SimpleNamespace(datapath=old_dp))

    assert c._datapaths.get(7) is new_dp
    assert c._pkt_in_count[7] == 42
    assert 7 in c._port_counts


def scenario_own_disconnect_still_pops_state():
    c = make_controller()
    dp = FakeDP(7)
    c._datapaths[7] = dp
    c._pkt_in_count[7] = 42

    c.switch_disconnect_handler(SimpleNamespace(datapath=dp))

    assert 7 not in c._datapaths
    assert 7 not in c._pkt_in_count


def scenario_handle_ipv4_drops_banned_src_early():
    c = make_controller()
    c._banned_ips.add("10.0.0.66")
    dp = FakeDP(1)
    eth = SimpleNamespace(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    ip4 = SimpleNamespace(src="10.0.0.66", dst="10.0.0.20", proto=6)

    c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1, None,
                   eth, ip4, None)

    assert dp.sent == []
    assert "aa:bb:cc:dd:ee:ff" not in c._mac_to_port[1]


def scenario_handle_ipv4_still_forwards_unbanned_src():
    c = make_controller()
    dp = FakeDP(1)
    eth = SimpleNamespace(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    ip4 = SimpleNamespace(src="10.0.0.30", dst="10.0.0.20", proto=6)
    pkt = SimpleNamespace(get_protocol=lambda proto: None)

    c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1,
                   SimpleNamespace(data=frame("10.0.0.30"),
                                   buffer_id=FakeOfp.OFP_NO_BUFFER,
                                   match={{"in_port": 1}}),
                   eth, ip4, pkt)

    assert len(installs(dp)) == 1


def scenario_throttle_dedup_skips_reinstall_within_ttl():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)

    assert throttle_call(c, dp, "10.0.0.66") is True
    first = len(installs(dp))
    assert first == 1

    assert throttle_call(c, dp, "10.0.0.66") is True
    assert len(installs(dp)) == first


def scenario_throttle_install_cap_bounds_unique_installs():
    c = make_controller()
    c._INSTALL_CAP_PER_SEC = 2
    dp = FakeDP(1)
    over_limit(c)

    for i in range(5):
        assert throttle_call(c, dp, "10.0.1.%d" % i) is True

    assert len(installs(dp)) == 2


def scenario_below_limit_path_unaffected_by_cap():
    c = make_controller()
    c._INSTALL_CAP_PER_SEC = 1
    dp = FakeDP(1)

    for i in range(3):
        c._handle_ipv4(dp, dp.ofproto, dp.ofproto_parser, 1, 1,
                       SimpleNamespace(data=frame("10.0.2.%d" % i),
                                       buffer_id=FakeOfp.OFP_NO_BUFFER,
                                       match={{"in_port": 1}}),
                       SimpleNamespace(src="aa:bb:cc:dd:ee:0%d" % i,
                                       dst="11:22:33:44:55:66"),
                       SimpleNamespace(src="10.0.2.%d" % i, dst="10.0.0.20",
                                       proto=6),
                       SimpleNamespace(get_protocol=lambda proto: None))

    assert len(installs(dp)) == 3


def scenario_block_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    c._banned_ips.add("10.0.0.66")
    c._datapaths[1] = dp
    c._apply_command({{"action": "block", "src_ip": "10.0.0.66", "ttl": 30}})

    # Rule deleted by the block install: a later packet must reinstall,
    # never be swallowed by a stale dedup entry.
    c._banned_ips.discard("10.0.0.66")
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_clear_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")

    c._datapaths[1] = dp
    c._apply_command({{"action": "clear", "src_ip": "10.0.0.66"}})

    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_epoch_delete_invalidates_dedup_entry():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    stat = SimpleNamespace(packet_count=5, byte_count=500, duration_sec=601,
                           duration_nsec=0, priority=10,
                           match={{"ipv4_src": "10.0.0.66"}},
                           idle_timeout=60, hard_timeout=0, flags=0)
    c._switch_agg[1].update({{"last_reply_ts": time.time() - 1.0,
                              "disp_interval": 1.0}})
    c.flow_stats_reply_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp, body=[stat])))

    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_throttle_dedup_expires_after_ttl():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    # Age the dedup entry past the TTL (62s > 60): the rule is gone, so the
    # next packet must reinstall, never be swallowed.
    c._recent_installs[1]["10.0.0.66"] -= 62.0

    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_stats_sighting_does_not_extend_dedup():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1

    # A stats sighting of a live p10 entry proves presence, but it must NOT
    # extend the dedup TTL: entries die with their rule (idle 60s). Without
    # this, a host that pauses >60s is blackholed for up to ~60s on resume.
    stat = SimpleNamespace(packet_count=300, byte_count=30000, duration_sec=70,
                           duration_nsec=0, priority=10,
                           match={{"ipv4_src": "10.0.0.66"}},
                           idle_timeout=60, hard_timeout=0, flags=0)
    c._switch_agg[1].update({{"last_reply_ts": time.time() - 1.0,
                              "disp_interval": 1.0}})
    c.flow_stats_reply_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp, body=[stat])))

    c._recent_installs[1]["10.0.0.66"] -= 62.0
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_install_drop_rule_forgets_via_real_ofpmatch():
    from ryu.ofproto.ofproto_v1_3_parser import OFPMatch

    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1
    assert "10.0.0.66" in c._recent_installs[1]

    # Production passes a REAL ryu OFPMatch (not a dict) to the drop-rule
    # install; the dedup invalidation must work through OFPMatch.get().
    real_match = OFPMatch(eth_type=0x0800, ipv4_src="10.0.0.66")
    c._install_drop_rule(dp, dp.ofproto, dp.ofproto_parser, real_match,
                         "block", 30)

    assert "10.0.0.66" not in c._recent_installs[1]


def scenario_reconnect_flush_invalidates_dedup():
    c = make_controller()
    dp = FakeDP(1)
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 1
    assert "10.0.0.66" in c._recent_installs[1]

    # TCP flap: the switch reconnects and the features-handler flush wipes
    # the flow table (non-strict wildcard DELETE). Dedup entries for that
    # dpid must die with their rules; otherwise packet-ins for srcs
    # installed pre-flap are swallowed for up to INSTALL_DEDUP_TTL_S
    # against an empty table.
    c.switch_features_handler(SimpleNamespace(
        msg=SimpleNamespace(datapath=dp)))

    assert 1 not in c._recent_installs
    assert 1 not in c._install_budget

    # Post-reconnect packet from the same src must reinstall, not be
    # swallowed by the stale presumed-live entry.
    over_limit(c)
    throttle_call(c, dp, "10.0.0.66")
    assert len(installs(dp)) == 2


def scenario_meter_install_deletes_before_add():
    c = make_controller()
    dp = FakeDP(1)

    c._install_rate_limit_meter(dp, dp.ofproto, dp.ofproto_parser)

    meters = [m for m in dp.sent if getattr(m, "msg_type", "") == "meter"]
    assert len(meters) == 2
    assert meters[0].command == FakeOfp.OFPMC_DELETE
    assert meters[1].command == FakeOfp.OFPMC_ADD


def scenario_error_msg_handler_exists_and_is_rate_limited():
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


SCENARIOS = {{
    name[len("scenario_"):]: fn
    for name, fn in sorted(globals().items())
    if name.startswith("scenario_")
}}


def main():
    results = {{}}
    for name, fn in SCENARIOS.items():
        try:
            fn()
            results[name] = "pass"
        except Exception:
            results[name] = "FAIL: " + traceback.format_exc(limit=5)
    print(json.dumps(results))


main()
'''.format(repo_root=str(HERE.resolve().parents[1]))


def run_scenarios():
    proc = subprocess.run(
        [sys.executable, "-c", WORKER],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError("worker crashed:\n" + proc.stderr[-2000:])
    return json.loads(proc.stdout.strip().splitlines()[-1])


_SCENARIO_NAMES = [
    "stale_disconnect_keeps_new_datapath",
    "own_disconnect_still_pops_state",
    "handle_ipv4_drops_banned_src_early",
    "handle_ipv4_still_forwards_unbanned_src",
    "throttle_dedup_skips_reinstall_within_ttl",
    "throttle_install_cap_bounds_unique_installs",
    "below_limit_path_unaffected_by_cap",
    "block_invalidates_dedup_entry",
    "clear_invalidates_dedup_entry",
    "epoch_delete_invalidates_dedup_entry",
    "throttle_dedup_expires_after_ttl",
    "stats_sighting_does_not_extend_dedup",
    "install_drop_rule_forgets_via_real_ofpmatch",
    "reconnect_flush_invalidates_dedup",
    "meter_install_deletes_before_add",
    "error_msg_handler_exists_and_is_rate_limited",
]

_RESULTS = None


def _results():
    global _RESULTS
    if _RESULTS is None:
        _RESULTS = run_scenarios()
    return _RESULTS


def _make_test(name):
    def _t():
        verdict = _results().get(name)
        assert verdict == "pass", verdict
    _t.__name__ = "test_scenario_" + name
    _t.__doc__ = "Subprocess scenario: " + name
    return _t


for _name in _SCENARIO_NAMES:
    globals()["test_scenario_" + _name] = _make_test(_name)
