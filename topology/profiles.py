import random

SERVER_IP = "10.0.0.26"
SINKHOLE_IP = "10.0.0.27"

ATTACK_PKT_COUNTS = {
    "SYN": 20000,
    "UDP": 8000,
    "ICMP": 12000,
}


def attack_pkt_count(atype: str) -> int:
    return ATTACK_PKT_COUNTS.get(atype, 10000)


_attack_pkt_count = attack_pkt_count

_LEGIT_NUMS = frozenset(range(1, 16))
_ATTACKER_NUMS = frozenset(range(16, 26))
_ATTACKER_POOL = _ATTACKER_NUMS

_ALL_VARIANTS = {
    16: ("SYN", "-S -p 80 --flood", 0, 0),
    17: ("SYN", "-S -p 443 --flood", 0, 0),
    18: ("SYN", "-S -p 5432 --flood", 0, 0),
    19: ("SYN", "-S -p 8080 --flood", 0, 0),
    20: ("UDP", "--udp -p 53 --flood --data 1400", 0, 0),
    21: ("UDP", "--udp -p 123 --flood --data 1400", 0, 0),
    22: ("UDP", "--udp -p 1900 --flood --data 1400", 0, 0),
    23: ("ICMP", "--icmp --flood --data 512", 0, 0),
    24: ("ICMP", "--icmp --flood --data 512", 0, 0),
    25: ("ICMP", "--icmp --flood --data 512", 0, 0),
}
_ATTACKER_VARIANTS = {n: v for n, v in _ALL_VARIANTS.items() if n in _ATTACKER_NUMS}

_STRESS_CMDS = {}
for _n, (_t, _fl, _, _) in _ATTACKER_VARIANTS.items():
    if _t == "SYN":
        _core = f"{_fl} --rand-source"
    else:
        _core = _fl.replace("--data ", "--rand-source --data ", 1)
    _STRESS_CMDS[_n] = f"hping3 {_core} {SERVER_IP} > /dev/null 2>&1"
del _n, _t, _fl

_ATTACKER_START_DELAYS = {
    num: round(random.uniform(0.1, 0.6), 2) for num in _ATTACKER_NUMS
}

_ATTACK_TYPE_FLAGS = {
    "SYN": "-S -p {port} --flood",
    "UDP": "--udp -p {port} --flood --data 1400",
    "ICMP": "--icmp --flood --data 512",
}
_ATTACK_TYPE_PORTS = {
    "SYN": [80, 443, 8080, 5432, 3389, 25, 1900],
    "UDP": [53, 123, 1900, 11211, 161, 514],
    "ICMP": [0],
}

_SYN_FLOOD_INSTANCES = 2


def flood_spawn_count(atype: str) -> int:
    return _SYN_FLOOD_INSTANCES if atype == "SYN" else 1


_flood_spawn_count = flood_spawn_count

_ICMP_CONTINUOUS = {
    0: (56, 56, 6.0, 10.0),
    1: (56, 56, 12.0, 20.0),
    3: (56, 56, 5.0, 8.0),
}

_TCP_PROFILES = {
    80: (32, 128, 5.0, 10.0),
    443: (32, 128, 5.0, 10.0),
    8080: (32, 128, 5.0, 10.0),
}

_UDP_PROFILES = {
    53: (32, 128, 6.0, 12.0),
    123: (32, 128, 8.0, 15.0),
    161: (32, 128, 10.0, 20.0),
    514: (32, 128, 5.0, 10.0),
    1900: (32, 128, 8.0, 15.0),
}

_LEGIT_SLEEP_MULTIPLIERS = {
    6: 2.5,
    8: 1.5,
    9: 2.5,
    10: 1.5,
}

_HOST_SLOTS = {
    1: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    2: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    3: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    4: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    5: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    6: [("udp", 53), ("udp", 514)],
    7: [("udp", 123), ("udp", 161)],
    8: [("udp", 1900), ("udp", 53)],
    9: [("udp", 514), ("udp", 123)],
    10: [("udp", 161), ("udp", 1900)],
    11: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
    12: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
    13: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
    14: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
    15: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
}


def post_idle_slots(num: int) -> list:
    return list(_HOST_SLOTS.get(num, [("icmp_cont", 1)]))


_post_idle_slots = post_idle_slots

_DEFAULT_DURATIONS = {
    "idle": (8, 20),
    "active": (45, 45),
}
