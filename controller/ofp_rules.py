import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.mitigation.traffic_filter import RATE_LIMIT_PPS

RATE_LIMIT_METER_ID = 1
DROP_PRIORITY = {"block": 100, "quarantine": 90, "rate_limit": 80}
ALL_DROP_PRIORITIES = (50, 80, 90, 100)
INSTALL_DEDUP_TTL_S = 60


def delete_flow(dp, parser, ofp, match, priority, *, strict=True):
    cmd = ofp.OFPFC_DELETE_STRICT if strict else ofp.OFP_DELETE
    dp.send_msg(parser.OFPFlowMod(
        datapath=dp, command=cmd,
        priority=priority,
        out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
        match=match,
    ))


def install_forward(dp, parser, ofp, match, out_port, buffer_id, *, priority=10, idle_timeout=INSTALL_DEDUP_TTL_S):
    actions = [parser.OFPActionOutput(out_port)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    dp.send_msg(parser.OFPFlowMod(
        datapath=dp, priority=priority,
        idle_timeout=idle_timeout, hard_timeout=0,
        buffer_id=buffer_id, match=match, instructions=inst,
    ))


def install_drop(dp, parser, ofp, match, priority, *, hard_timeout=0, instructions=None):
    dp.send_msg(parser.OFPFlowMod(
        datapath=dp, priority=priority,
        idle_timeout=0, hard_timeout=hard_timeout,
        match=match, instructions=instructions or [],
    ))


def install_rate_limit_meter(dp, ofp, parser, meter_id=RATE_LIMIT_METER_ID, rate_limit_pps=RATE_LIMIT_PPS):
    dp.send_msg(parser.OFPMeterMod(
        datapath=dp,
        command=ofp.OFPMC_DELETE,
        flags=ofp.OFPMF_PKTPS,
        meter_id=meter_id,
        bands=[],
    ))
    bands = [parser.OFPMeterBandDrop(
        type_=ofp.OFPMBT_DROP,
        rate=rate_limit_pps,
        burst_size=rate_limit_pps // 10,
    )]
    dp.send_msg(parser.OFPMeterMod(
        datapath=dp,
        command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS,
        meter_id=meter_id,
        bands=bands,
    ))


def build_drop_flow_mods(dp, ofp, parser, match, action: str, ttl=None, drop_priorities=None, meter_id=RATE_LIMIT_METER_ID):
    pri_map = drop_priorities or DROP_PRIORITY
    drop_pri = pri_map[action]
    hard_timeout = int(ttl) if (action == "block" and ttl is not None) else 0

    for cmd_type, pri in [
        (ofp.OFPFC_DELETE_STRICT, 10),
        (ofp.OFPFC_DELETE_STRICT, 85),
        (ofp.OFPFC_DELETE_STRICT, 1),
        (ofp.OFPFC_DELETE_STRICT, drop_pri),
    ]:
        delete_flow(dp, parser, ofp, match, pri, strict=True)

    if action == "rate_limit":
        meter_inst = [
            parser.OFPInstructionMeter(meter_id),
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
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=drop_pri,
            idle_timeout=0, hard_timeout=hard_timeout,
            match=match, instructions=[],
        ))


def apply_proto_block_rule(dp, ofp, parser, proto: int, remove: bool = False, dpid: int = 0, logger=None):
    proto_match = parser.OFPMatch(eth_type=0x0800, ip_proto=proto)
    if remove:
        delete_flow(dp, parser, ofp, proto_match, priority=50, strict=True)
        if logger:
            logger.debug("Proto drop removed: nw_proto=%d on dpid=%016x", proto, dpid)
    else:
        install_drop(dp, parser, ofp, proto_match, priority=50, hard_timeout=0)
        if logger:
            logger.debug("Proto drop installed: nw_proto=%d on dpid=%016x", proto, dpid)


def build_clear_flow_mods(dp, ofp, parser, match):
    for pri in (100, 90, 85, 80, 10):
        delete_flow(dp, parser, ofp, match, pri, strict=True)

    permit_inst = [parser.OFPInstructionActions(
        ofp.OFPIT_APPLY_ACTIONS,
        [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
    )]
    dp.send_msg(parser.OFPFlowMod(
        datapath=dp, priority=5,
        idle_timeout=10, hard_timeout=10,
        match=match, instructions=permit_inst,
    ))


def build_redirect_flow_mods(dp, ofp, parser, match, redirect_to: str):
    for pri in (10, 85):
        delete_flow(dp, parser, ofp, match, pri, strict=True)

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
