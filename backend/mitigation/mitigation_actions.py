# Dispatches mitigation commands to the Ryu SDN controller via ZMQ commander.
# Handles command packaging and logging failure states gracefully.

import logging

log = logging.getLogger(__name__)


def _send_command(payload: dict, desc: str, critical: bool = False) -> bool:
    # Sends a command dictionary to the ZMQ commander and logs the outcome.
    # Returns True on success, or False if transport or controller communication fails.
    try:
        from backend.mitigation.zmq_commander import commander
        commander.send(payload)
        if critical:
            log.critical("Mitigation: %s", desc)
        else:
            log.info("Mitigation: %s", desc)
        return True
    except Exception as exc:
        log.warning("Mitigation: failed to %s: %s", desc, exc)
        return False


def install_per_ip_meters(ips: list[str], rate_pps: int = 100) -> bool:
    # Installs per-IP rate meters on OpenFlow switches for detected attacker addresses.
    # Limits individual IP packet rates to prevent link and queue exhaustion.
    payload = {
        "action": "per_ip_meters",
        "ips": ips,
        "rate_pps": rate_pps,
    }
    desc = f"per-IP meters installed for {len(ips)} IPs at {rate_pps} pps"
    return _send_command(payload, desc)


def remove_per_ip_meters() -> bool:
    # Removes all active per-IP rate meters from switches.
    # Restores default flow processing when attack conditions subside.
    return _send_command({"action": "remove_per_ip_meters"}, "per-IP meters removed")


def install_proto_block(protos: set) -> bool:
    # Deprecated for automatic guard use: blanket protocol drops also drop
    # benign traffic that shares the protocol (see
    # notes/tasks/benign-traffic-blackout-proto-block-fix-plan.md).
    # New automatic code must use install_per_ip_meters().
    # remove_proto_block() stays for one-time cleanup of stale priority 50 rules only.
    # Installs blanket protocol drop rules on switches for attack protocols.
    # Drops targeted protocol traffic immediately at switch ingress ports.
    if not protos:
        return False
    all_ok = True
    for proto in protos:
        payload = {"action": "proto_block", "proto": proto, "remove": False}
        desc = f"BLANKET proto_block installed for proto={proto}"
        if not _send_command(payload, desc, critical=True):
            all_ok = False
    return all_ok


def remove_proto_block(protos: set) -> bool:
    # Removes blanket protocol drop rules from OpenFlow switches.
    # Re-enables legitimate protocol traffic across the network topology.
    all_ok = True
    for proto in protos:
        payload = {"action": "proto_block", "proto": proto, "remove": True}
        desc = f"proto_block removed for proto={proto}"
        if not _send_command(payload, desc):
            all_ok = False
    return all_ok
