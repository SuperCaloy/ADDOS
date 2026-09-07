import logging

log = logging.getLogger(__name__)


def install_per_ip_meters(ips: list[str], rate_pps: int = 100) -> bool:
    """Install per-IP meters via ZMQ command to controller."""
    try:
        from backend.transport.zmq_commander import commander
        commander.send({
            "action": "per_ip_meters",
            "ips": ips,
            "rate_pps": rate_pps,
        })
        log.info("Mitigation: per-IP meters installed for %d IPs at %d pps", len(ips), rate_pps)
        return True
    except Exception as exc:
        log.warning("Mitigation: failed to install per-IP meters: %s", exc)
        return False


def remove_per_ip_meters() -> bool:
    """Remove all per-IP meters via ZMQ command to controller."""
    try:
        from backend.transport.zmq_commander import commander
        commander.send({"action": "remove_per_ip_meters"})
        log.info("Mitigation: per-IP meters removed")
        return True
    except Exception as exc:
        log.warning("Mitigation: failed to remove per-IP meters: %s", exc)
        return False


def install_proto_block(protos: set) -> bool:
    """Install blanket proto_block for all attack protocols."""
    try:
        from backend.transport.zmq_commander import commander
        for proto in protos:
            commander.send({"action": "proto_block", "proto": proto, "remove": False})
            log.critical("Mitigation: BLANKET proto_block installed for proto=%s", proto)
        return len(protos) > 0
    except Exception as exc:
        log.warning("Mitigation: failed to install blanket block: %s", exc)
        return False


def remove_proto_block(protos: set) -> bool:
    """Remove blanket proto_block for all attack protocols."""
    try:
        from backend.transport.zmq_commander import commander
        for proto in protos:
            commander.send({"action": "proto_block", "proto": proto, "remove": True})
            log.info("Mitigation: proto_block removed for proto=%s", proto)
        return True
    except Exception as exc:
        log.warning("Mitigation: failed to remove proto_block: %s", exc)
        return False
