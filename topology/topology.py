import time
import random
import subprocess
import threading
import urllib.request
import json as _json
import logging as _logging
import warnings
warnings.filterwarnings("ignore", message=".*zmq.*")
_logging.getLogger("ryu.lib.hub").setLevel(_logging.ERROR)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link

# === CONSTANTS ===
CONTROLLER_IP    = "127.0.0.1"
CONTROLLER_PORT  = 6633
BACKEND_API      = "http://127.0.0.1:5000"
RESTORE_POLL_S   = 5.0
N_EDGE           = 8
N_HOSTS          = 20
SERVER_IP        = "10.0.0.20"   # h20 — victim HTTP server
SINKHOLE_IP      = "10.0.0.21"   # h21 — silent dummy host for sinkhole redirection
ATTACK_PKT_COUNT = 5000
WHITELIST_IPS    = {SERVER_IP, SINKHOLE_IP}  # never ML-scored

# h1-h5 = legit, h6-h19 = attacker
_ATTACKER_NUMS = {6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
_LEGIT_NUMS    = {1, 2, 3, 4, 5}

# Each attacker has a distinct hping3 signature -- varied intensity and technique
# SYN: mix of full flood, rate-limited, and spoofed source
# ICMP: mix of full flood, large payload, spoofed source, small payload
# UDP: mix of full flood, rate-limited, random destination port
_ATTACKER_VARIANTS = {
    # SYN — max to high
    6:  ("SYN",  "-S -p 80  --flood"),
    7:  ("SYN",  "-S -p 443 --flood"),
    8:  ("SYN",  "-S -p 8080 -i u100 --data 1400"),
    9:  ("SYN",  "-S -p 8443 -i u500 --data 1400"),
    # ICMP — max to high
    10: ("ICMP", "--icmp --flood --data 1400"),
    11: ("ICMP", "--icmp --flood"),
    12: ("ICMP", "--icmp -i u100 --data 1400"),
    13: ("ICMP", "--icmp -i u500 --data 512"),
    # UDP — max to high
    14: ("UDP",  "--udp -p 53  --flood --data 1400"),
    15: ("UDP",  "--udp -p 80  --flood --data 1400"),
    16: ("UDP",  "--udp -p 443 -i u100 --data 1400"),
    17: ("UDP",  "--udp -p 123 -i u500 --data 1400"),
    18: ("UDP",  "--udp -p 53  -i u1000 --data 512"),
    # SYN variant — high
    19: ("SYN",  "-S -p 80 -i u100"),
}

# Staggered start delays per attacker (seconds) -- SYN wave first, ICMP mid, UDP last
# Simulates imperfect botnet coordination -- nodes do not all start simultaneously
_ATTACKER_START_DELAYS = {
    # SYN wave
    6:  0,
    7:  3,
    8:  5,
    9:  7,
    # ICMP wave
    10: 12,
    11: 15,
    12: 18,
    13: 21,
    # UDP wave
    14: 26,
    15: 29,
    16: 32,
    17: 35,
    # Mixed
    18: 40,
    19: 43,
}

# Per-attacker cycle: (attack_min, attack_max, rest_min, rest_max) in seconds
# Based on real botnet behavior (Mirai, Bashlite) -- each node has different capacity
# Attack duration varies per cycle -- picked fresh each time from the range
_ATTACKER_CYCLES = {
    # SYN: short bursts (5-15s attack, 3-8s rest)
    6:  (5,  15,  3,  8),
    7:  (8,  15,  3,  8),
    8:  (10, 20,  4,  8),
    9:  (5,  12,  3,  6),
    # ICMP: medium sustained (20-60s attack, 5-12s rest)
    10: (30, 60,  5, 12),
    11: (20, 50,  5, 10),
    12: (25, 55,  6, 12),
    13: (20, 45,  5, 10),
    # UDP: long sustained (60-120s attack, 10-25s rest)
    14: (60, 120, 10, 25),
    15: (60, 100, 10, 20),
    16: (70, 120, 12, 25),
    17: (60, 110, 10, 22),
    # UDP slow + SYN variant
    18: (60, 120, 10, 25),
    19: (5,  15,   3,  8),
}

# Global stop event for mixed campaign threads
_mixed_stop_event = threading.Event()
# Track active campaign threads
_campaign_threads: list = []

# Per-host traffic profiles: state → (interval_range, duration_range)
# Max pps hard cap = 100 pps per host across all states
# downloading min interval 0.010s = 100 pps max
# watching   min interval 0.012s = ~83 pps max
# browsing   already well below 100 pps — unchanged
# Each host has distinct pps range — no two hosts share the same rate
# Max 50 pps per host in any state -- clear separation from rate-limited attacks (~1000 pps)
# Minimum interval = 0.020s = 50 pps hard cap
# h1-h5 legit hosts max 40pps
# max 40pps = min interval 0.025s
_HOST_BASELINE_PROFILES = {
    1: {"idle": ((0.5,  1.5),  (10, 30)), "browsing": ((0.025, 0.06),  (5, 12)), "watching": ((0.025, 0.05), (20, 80)),  "downloading": ((0.025, 0.05), (8, 20))},
    2: {"idle": ((0.6,  1.8),  (10, 30)), "browsing": ((0.030, 0.08),  (5, 12)), "watching": ((0.030, 0.06), (20, 80)),  "downloading": ((0.030, 0.06), (8, 20))},
    3: {"idle": ((0.8,  2.0),  (12, 35)), "browsing": ((0.040, 0.10),  (5, 15)), "watching": ((0.040, 0.08), (25, 90)),  "downloading": ((0.040, 0.08), (8, 25))},
    4: {"idle": ((1.0,  2.5),  (12, 35)), "browsing": ((0.050, 0.12),  (5, 15)), "watching": ((0.050, 0.10), (30, 100)), "downloading": ((0.050, 0.10), (10, 30))},
    5: {"idle": ((1.2,  3.0),  (15, 40)), "browsing": ((0.060, 0.15),  (5, 15)), "watching": ((0.060, 0.12), (30, 110)), "downloading": ((0.060, 0.12), (10, 30))},
}

_DEFAULT_DURATIONS = {
    "idle": (10, 30), "browsing": (5, 15), "watching": (30, 120), "downloading": (10, 30),
}

# Per-host ICMP variant — each legit host uses a distinct ping signature
# Varies by: payload size (-s), TTL (-t), IPv6 (ping6), flood type
# No two hosts share the same command template
_HOST_ICMP_VARIANT = {
    1: lambda ip, interval: f"ping -i {interval} -s 64  {ip}",
    2: lambda ip, interval: f"ping -i {interval} -s 128 {ip}",
    3: lambda ip, interval: f"ping -i {interval} -s 256 {ip}",
    4: lambda ip, interval: f"ping -i {interval} -s 32  {ip}",
    5: lambda ip, interval: f"ping -i {interval} -s 512 {ip}",
}

# Runtime state — populated at startup
_host_switch_map:    dict[str, str]              = {}
_attack_assignments: list[dict]                  = []
_baseline_threads:   dict[str, threading.Thread] = {}
_baseline_stop:      dict[str, threading.Event]  = {}
_restore_log = _logging.getLogger("restore_poller")

# Global net/hosts — set at startup, used by all commands
net   = None
hosts = []


# === TOPOLOGY ===

def _weighted_distribute(n_hosts: int, n_switches: int) -> list[int]:
    # Distribute hosts across switches, weighted toward 1-2 per switch
    weights  = [40, 35, 15, 8, 2]
    counts   = [0] * n_switches
    assigned = 0
    for i in range(n_switches):
        if assigned >= n_hosts:
            break
        remaining_sw = n_switches - i
        remaining_h  = n_hosts - assigned
        max_here     = min(remaining_h - (remaining_sw - 1), 5)
        choices      = list(range(1, max_here + 1))
        count        = random.choices(choices, weights=weights[:len(choices)], k=1)[0]
        counts[i]    = count
        assigned    += count
    counts[-1] += n_hosts - sum(counts)
    random.shuffle(counts)
    return counts


def build_star(n_hosts: int = N_HOSTS, n_edge: int = N_EDGE):
    # 1 core switch + n_edge edge switches, hosts on flat 10.0.0.x/24
    global _host_switch_map
    _net = Mininet(
        controller=None, switch=OVSKernelSwitch,
        link=Link, autoSetMacs=True, autoStaticArp=True,
    )
    _net.addController("c0", controller=RemoteController,
                       ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    core = _net.addSwitch("s0", dpid=f"{1:016x}")
    edge_switches = []
    for i in range(1, n_edge + 1):
        sw = _net.addSwitch(f"s{i}", dpid=f"{i + 1:016x}")
        _net.addLink(core, sw)
        edge_switches.append(sw)

    distribution = _weighted_distribute(n_hosts, n_edge)
    _hosts, host_num = [], 1
    for sw, count in zip(edge_switches, distribution):
        for _ in range(count):
            ip   = f"10.0.0.{host_num}"
            mac  = f"00:00:00:00:00:{host_num:02x}"
            host = _net.addHost(f"h{host_num}", ip=f"{ip}/24", mac=mac)
            _net.addLink(host, sw)
            _hosts.append(host)
            _host_switch_map[f"h{host_num}"] = sw.name
            host_num += 1

    # h21 — silent sinkhole dummy host
    # Connected directly to core switch s0
    # Receives redirected uncertain traffic — never sends anything
    sinkhole = _net.addHost(
        "h21",
        ip=f"{SINKHOLE_IP}/24",
        mac="00:00:00:00:00:15",
    )
    _net.addLink(sinkhole, core)
    _host_switch_map["h21"] = core.name

    return _net, _hosts, edge_switches, distribution


def _assign_attacks() -> list[dict]:
    # Map each attacker to its fixed hping3 variant
    global _attack_assignments
    _attack_assignments = []
    for h in hosts:
        num = int(h.name[1:])
        if num in _ATTACKER_NUMS:
            attack_type, flags = _ATTACKER_VARIANTS[num]
            _attack_assignments.append({
                "attacker": h.name, "attack_type": attack_type,
                "flags": flags, "target": SERVER_IP,
            })
    return _attack_assignments


# === BASELINE TRAFFIC ===

def _nsrun(host, cmd: str, wait: bool = False) -> None:
    # Run command in host netns via nsenter — avoids Mininet poll() conflicts in threads
    full = f"nsenter -t {host.pid} -n -- bash -c {cmd!r}"
    if wait:
        subprocess.run(full, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(full, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# Per-host TCP/UDP ports for mixed baseline — each host has distinct ports
_HOST_TCP_PORT = {1: 80, 2: 443, 3: 8080, 4: 22, 5: 3306}
_HOST_UDP_PORT = {1: 53, 2: 123, 3: 5353, 4: 67, 5: 161}

# Traffic type rotation per state
# browsing/downloading cycle: ICMP -> TCP -> UDP
# watching: ICMP -> UDP
# idle: ICMP only
_TRAFFIC_ROTATION = {
    "browsing":     ["icmp", "tcp", "udp"],
    "watching":     ["icmp", "udp"],
    "downloading":  ["icmp", "tcp", "udp"],
    "idle":         ["icmp"],   # slow ping kept alive — no silence
}


# Fixed starting state per host — staggered so there is always a mix active
# 2-3 hosts start in each state, guarantees diversity from the first second
_HOST_START_STATE = {
    1: "browsing",
    2: "watching",
    3: "downloading",
    4: "idle",
    5: "browsing",
}

# Deterministic cycle order — each host advances through this after each duration
_STATE_CYCLE = ["browsing", "watching", "downloading", "idle"]


def _kill_baseline_procs(host) -> None:
    _nsrun(host, "pkill -f 'ping -i' 2>/dev/null; pkill -f hping3 2>/dev/null; true", wait=True)


def _start_traffic(host, num: int, traffic_type: str, interval: float) -> None:
    # Launch one traffic leg — ICMP, TCP, or UDP
    if traffic_type == "icmp":
        icmp_fn  = _HOST_ICMP_VARIANT.get(num)
        cmd = icmp_fn(SERVER_IP, interval) if icmp_fn else f"ping -i {interval} {SERVER_IP}"
        _nsrun(host, f"{cmd} > /dev/null 2>&1")
    elif traffic_type == "tcp":
        port = _HOST_TCP_PORT.get(num, 80)
        # hping3 SYN at interval -- stays well under 50 pps
        _nsrun(host, f"hping3 -S -p {port} -i u{int(interval*1_000_000)} {SERVER_IP} > /dev/null 2>&1")
    elif traffic_type == "udp":
        port = _HOST_UDP_PORT.get(num, 53)
        _nsrun(host, f"hping3 --udp -p {port} -i u{int(interval*1_000_000)} {SERVER_IP} > /dev/null 2>&1")


def _baseline_loop(host, stop_event: threading.Event) -> None:
    num      = int(host.name[1:])
    profile  = _HOST_BASELINE_PROFILES.get(num)

    start_state = _HOST_START_STATE.get(num, "browsing")
    cycle_idx   = _STATE_CYCLE.index(start_state) if start_state in _STATE_CYCLE else 0
    traffic_idx = 0  # rotates through traffic types per state

    while not stop_event.is_set():
        state_name = _STATE_CYCLE[cycle_idx % len(_STATE_CYCLE)]
        cycle_idx += 1

        if profile and state_name in profile:
            interval_range, duration_range = profile[state_name]
        else:
            interval_range = (0.5, 2.0)
            duration_range = _DEFAULT_DURATIONS.get(state_name, (10, 30))

        # idle uses very slow ping (1-3s interval) — traffic never fully stops
        if state_name == "idle":
            interval = round(random.uniform(1.0, 3.0), 4)
        else:
            interval = round(random.uniform(*interval_range), 4)
        duration = random.randint(*duration_range)

        # Pick next traffic type in rotation for this state
        rotation     = _TRAFFIC_ROTATION.get(state_name, ["icmp"])
        traffic_type = rotation[traffic_idx % len(rotation)]
        traffic_idx += 1

        _kill_baseline_procs(host)
        _start_traffic(host, num, traffic_type, interval)

        for _ in range(duration):
            if stop_event.is_set():
                break
            time.sleep(1)

    _kill_baseline_procs(host)


def start_baseline_traffic() -> None:
    # Start dynamic baseline thread for every legit host
    global _baseline_threads, _baseline_stop
    _stop_baseline_threads()
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
    info(f"*** Starting baseline on {len(legit)} legit hosts → {SERVER_IP}\n")
    for host in legit:
        stop_ev = threading.Event()
        t = threading.Thread(
            target=_baseline_loop, args=(host, stop_ev),
            name=f"baseline-{host.name}", daemon=True
        )
        _baseline_stop[host.name]    = stop_ev
        _baseline_threads[host.name] = t
        t.start()
        info(f"    {host.name} ({host.IP()}): started\n")


def _stop_baseline_threads() -> None:
    for ev in _baseline_stop.values():
        ev.set()
    for t in _baseline_threads.values():
        t.join(timeout=2)
    _baseline_threads.clear()
    _baseline_stop.clear()


def stop_baseline() -> None:
    info("*** Stopping baseline traffic...\n")
    _stop_baseline_threads()
    for h in net.hosts:
        h.cmd("pkill -f ping 2>/dev/null; true")
    info("    Done.\n")


# === SERVER ===

def start_server() -> None:
    # Start HTTP server on h20 (victim), whitelisted from ML scoring
    server = net.get("h20")
    server.cmd("pkill -f 'http.server' 2>/dev/null; true")
    server.cmd("python3 -m http.server 80 > /dev/null 2>&1 &")
    info(f"*** Server started on h20 ({SERVER_IP}:80) — whitelisted: {WHITELIST_IPS}\n")


# === ATTACKS ===

def _hping_cmd(attacker_num: int, target: str, count: int = None) -> str:
    # Build hping3 command from attacker variant config
    _, flags   = _ATTACKER_VARIANTS.get(attacker_num, ("SYN", "-S -p 80 --flood"))
    count_flag = f"-c {count} " if count else ""
    return f"hping3 {flags} {count_flag}{target}"


def _attacker_cycle_worker(num: int, stop_event: threading.Event) -> None:
    # Each attacker runs independently -- staggered start, random attack/rest cycles
    # Simulates real botnet node: different capacity, unpredictable timing
    h           = net.get(f"h{num}")
    delay       = _ATTACKER_START_DELAYS.get(num, 0)
    atk_min, atk_max, rst_min, rst_max = _ATTACKER_CYCLES.get(num, (15, 30, 5, 10))
    atype, _    = _ATTACKER_VARIANTS.get(num, ("SYN", ""))

    # Wait staggered start delay -- check stop_event every second
    for _ in range(delay):
        if stop_event.is_set():
            return
        time.sleep(1)

    while not stop_event.is_set():
        atk_dur = random.randint(atk_min, atk_max)
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")

        # Attack phase -- check stop every second
        for _ in range(atk_dur):
            if stop_event.is_set():
                break
            time.sleep(1)

        # Stop hping3 for rest phase
        _nsrun(h, "pkill -f hping3 2>/dev/null; true")

        if stop_event.is_set():
            break

        # Pick random rest duration for this cycle
        rst_dur = random.randint(rst_min, rst_max)
        pass  # silent rest

        for _ in range(rst_dur):
            if stop_event.is_set():
                break
            time.sleep(1)

    # Final cleanup
    _nsrun(h, "pkill -f hping3 2>/dev/null; true")


def launch_attack(sustained: bool = True) -> None:
    # Launch all 10 attackers simultaneously -- no stagger, no cycles
    # Use start_mixed_campaign() for realistic staggered cyclic behavior
    global _mixed_stop_event, _campaign_threads
    _mixed_stop_event.clear()
    count = None if sustained else ATTACK_PKT_COUNT
    info(f"*** {'Sustained' if sustained else 'Burst'} DDoS -- all attackers -> {SERVER_IP}\n\n")
    for a in _attack_assignments:
        num      = int(a["attacker"][1:])
        attacker = net.get(a["attacker"])
        cmd      = _hping_cmd(num, SERVER_IP, count)
        info(f"    {a['attacker']} ({attacker.IP()})  [{a['attack_type']}] {a['flags']}\n")
        _nsrun(attacker, f"{cmd} > /dev/null 2>&1")
    info("\n    -> Use  py stop_all_attacks()  to stop.\n")


def launch_syn_flood(attacker_name="h1") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** SYN burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_icmp_flood(attacker_name="h7") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** ICMP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_udp_flood(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** UDP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_syn_flood_sustained(attacker_name="h1") -> None:
    attacker = net.get(attacker_name)
    info(f"*** SYN sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def launch_icmp_flood_sustained(attacker_name="h7") -> None:
    attacker = net.get(attacker_name)
    info(f"*** ICMP sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def launch_udp_flood_sustained(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    info(f"*** UDP sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def start_syn_flood_campaign() -> None:
    # h1 (p80 flood), h3 (p443 rate-limited), h5 (p8080 spoofed), h17 (p8443 flood)
    info("*** [CAMPAIGN] SYN -- 4 attackers\n")
    for num in [1, 3, 5, 17]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> Use  py stop_all_attacks()  to stop.\n")


def start_icmp_flood_campaign() -> None:
    # h7 (flood), h9 (large payload rate-limited), h19 (spoofed src)
    info("*** [CAMPAIGN] ICMP -- 3 attackers\n")
    for num in [7, 9, 19]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> Use  py stop_all_attacks()  to stop.\n")


def start_udp_flood_campaign() -> None:
    # h11 (flood), h13 (rate-limited), h15 (rand-dest)
    info("*** [CAMPAIGN] UDP -- 3 attackers\n")
    for num in [11, 13, 15]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> Use  py stop_all_attacks()  to stop.\n")


def start_mixed_campaign() -> None:
    # All 10 attackers -- staggered starts, independent random attack/rest cycles
    # Each attacker thread runs until stop_all_attacks() is called
    global _mixed_stop_event, _campaign_threads
    _mixed_stop_event.clear()
    _campaign_threads.clear()

    info("*** [CAMPAIGN] Mixed -- staggered cyclic attack -- all 10 attackers\n")
    info("    SYN wave (h1,h3,h5,h17) -> ICMP wave (h7,h9,h19) -> UDP wave (h11,h13,h15)\n")
    info("    Each attacker: random attack duration, random rest, repeats until stopped\n\n")

    for num in sorted(_ATTACKER_VARIANTS.keys()):
        atype, flags = _ATTACKER_VARIANTS[num]
        delay        = _ATTACKER_START_DELAYS.get(num, 0)
        atk_min, atk_max, rst_min, rst_max = _ATTACKER_CYCLES.get(num, (15, 30, 5, 10))
        info(f"    h{num} [{atype}] {flags}\n"
             f"         start: +{delay}s | attack: {atk_min}-{atk_max}s | rest: {rst_min}-{rst_max}s\n")
        t = threading.Thread(
            target=_attacker_cycle_worker,
            args=(num, _mixed_stop_event),
            name=f"attacker-h{num}",
            daemon=True,
        )
        _campaign_threads.append(t)
        t.start()

    info("\n    -> Use  py stop_all_attacks()  to stop.\n")


def stop_all_attacks() -> None:
    # Signal all campaign threads to stop immediately
    global _mixed_stop_event, _campaign_threads
    _mixed_stop_event.set()

    # Kill hping3 on all attackers in parallel -- non-blocking
    info("*** Stopping all attacks (parallel kill)...\n")
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            _nsrun(h, "pkill -f hping3 2>/dev/null; true")

    # Wait briefly for parallel kills to land
    time.sleep(0.5)

    # Join campaign threads with short timeout
    for t in _campaign_threads:
        t.join(timeout=2)
    _campaign_threads.clear()

    info("*** Flushing OVS block rules...\n")
    for sw in net.switches:
        for pri in [100, 90, 80]:
            subprocess.run(f"ovs-ofctl del-flows {sw.name} priority={pri}",
                           shell=True, capture_output=True)

    info("*** Clearing controller state via ZMQ...\n")
    try:
        import zmq as _zmq
        _ctx  = _zmq.Context.instance()
        _sock = _ctx.socket(_zmq.PUSH)
        _sock.setsockopt(_zmq.LINGER, 0)
        _sock.setsockopt(_zmq.SNDTIMEO, 500)
        _sock.connect("tcp://127.0.0.1:5556")
        for h in hosts:
            if int(h.name[1:]) in _ATTACKER_NUMS:
                _sock.send_json({"action": "clear", "src_ip": h.IP()})
                info(f"    cleared: {h.IP()}\n")
        _sock.close()
    except Exception as e:
        info(f"    ZMQ warning: {e}\n")

    info("*** Flushing backend state (parallel)...\n")

    def _invalidate(ip):
        # Invalidate cache for one IP -- runs in parallel thread
        try:
            req = urllib.request.Request(
                f"{BACKEND_API}/api/cache/invalidate",
                data=_json.dumps({"src_ip": ip}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
        except Exception:
            pass

    # Run all cache invalidations in parallel
    inv_threads = []
    for h in hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            t = threading.Thread(target=_invalidate, args=(h.IP(),), daemon=True)
            inv_threads.append(t)
            t.start()
    for t in inv_threads:
        t.join(timeout=3)

    try:
        req2 = urllib.request.Request(
            f"{BACKEND_API}/api/quarantine/clear_all",
            data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req2, timeout=2) as r:
            resp = _json.loads(r.read())
        info(f"    quarantine cleared: {resp.get('cleared', 0)} entries\n")
    except Exception as e:
        info(f"    backend flush warning: {e}\n")

    info("*** Attack stopped -- forwarding restored.\n")


# === FLASH CROWD ===

# Max 300 pps per host -- safely below flood prefilter limits
# Diverse rates so hosts don't all look identical to IF
_FLASH_CROWD_PROFILES = {
    2:  ("0.0033", "~300 pps"),  # fastest -- capped at 300
    4:  ("0.004",  "~250 pps"),
    6:  ("0.006",  "~167 pps"),
    8:  ("0.010",  "~100 pps"),
    10: ("0.015",  "~67 pps"),
    12: ("0.025",  "~40 pps"),
    14: ("0.050",  "~20 pps"),
    16: ("0.100",  "~10 pps"),
    18: ("0.200",  "~5 pps"),
}


def _flash_crowd_worker(legit: list, duration: int) -> None:
    # Properly stop baseline threads before starting flash crowd
    _stop_baseline_threads()

    # Kill any existing ping/hping3 and wait for processes to die
    for h in legit:
        _nsrun(h, "pkill -f 'ping -i' 2>/dev/null; pkill -f hping3 2>/dev/null; true")
    time.sleep(1)

    # Start flash crowd ping per host at elevated rate
    for h in legit:
        num = int(h.name[1:])
        interval, label = _FLASH_CROWD_PROFILES.get(num, ("0.050", "~20 pps"))
        _nsrun(h, f"ping -i {interval} {SERVER_IP} > /dev/null 2>&1")
        info(f"    {h.name} ({h.IP()}): {label} -> {SERVER_IP}\n")

    # Wait for duration -- background thread so CLI stays responsive
    time.sleep(duration)

    # Stop flash crowd ping
    for h in legit:
        _nsrun(h, "pkill -f 'ping -i' 2>/dev/null; true")

    info("*** Flash crowd ended -- restoring baseline...\n")
    start_baseline_traffic()


def flash_crowd(duration: int = 30) -> None:
    # All legit hosts spike to server -- simulates viral/ticket-sale event
    # Runs in background thread -- CLI stays responsive during duration
    # Baseline automatically restores after duration seconds
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
    info(f"*** Flash crowd -- {len(legit)} legit hosts -> {SERVER_IP} for {duration}s\n")
    info(f"    CLI active -- baseline restores automatically after {duration}s\n\n")
    threading.Thread(
        target=_flash_crowd_worker, args=(legit, duration),
        name="flash-crowd", daemon=True
    ).start()


# === WARMUP ===

def _reset_ryu_state() -> None:
    # Send reset command to Ryu via ZMQ -- clears banned_ips, mac table,
    # ip_to_dpid map, counters from previous session before baseline starts
    info("*** Resetting Ryu in-memory state...\n")
    try:
        import zmq as _zmq
        _ctx  = _zmq.Context.instance()
        _sock = _ctx.socket(_zmq.PUSH)
        _sock.setsockopt(_zmq.LINGER, 0)
        _sock.setsockopt(_zmq.SNDTIMEO, 500)
        _sock.connect("tcp://127.0.0.1:5556")
        _sock.send_json({"action": "reset"})
        _sock.close()
        info("    Ryu state cleared.\n")
    except Exception as e:
        info(f"    Ryu reset warning: {e}\n")

def _warmup_macs() -> None:
    # Install FLOOD rules so warmup pings bypass Ryu entirely (no packet-in surge on startup)
    info("*** Warmup -- installing FLOOD rules (Ryu bypassed)...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl add-flow {sw.name} priority=0,actions=FLOOD",
                       shell=True, capture_output=True)

    # Each legit host pings server once in parallel -- only need ARP populated
    # Old N x N loop took ~110 sequential pings (up to 110s) -- this takes ~2s
    info("*** Pinging server in parallel to populate MAC tables...\n")
    legit = [h for h in hosts if int(h.name[1:]) not in _ATTACKER_NUMS]
    for src in legit:
        _nsrun(src, f"ping -c1 -W1 {SERVER_IP} > /dev/null 2>&1")
    time.sleep(2)

    # Remove FLOOD rules -- Ryu takes back full control
    info("*** Removing FLOOD rules -- Ryu resuming control...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl del-flows {sw.name} priority=0",
                       shell=True, capture_output=True)

    # 3s is enough for flows to age in Mininet (was 10s -- unnecessary delay)
    info("*** Waiting 3s for flows to age...\n")
    time.sleep(3)

    # Clear prefilter flags -- warmup pings accumulate burst counts
    # Without this legit hosts trip flood prefilter on first baseline ping
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from backend.pipeline.flood_prefilter import flood_filter as _ff
    for h in hosts:
        if int(h.name[1:]) not in _ATTACKER_NUMS:
            _ff.clear_flag(h.IP())
    info("*** Prefilter flags cleared for legit hosts.\n")
    info("*** Warmup complete.\n")


# === CHECK TRAFFIC ===

def _fetch_quarantine() -> dict:
    try:
        with urllib.request.urlopen(f"{BACKEND_API}/api/quarantine_list", timeout=2) as r:
            return {e["src_ip"]: e["phase"] for e in _json.loads(r.read())}
    except Exception:
        return {}


def _fetch_stats() -> dict:
    try:
        with urllib.request.urlopen(f"{BACKEND_API}/api/stats", timeout=2) as r:
            return _json.loads(r.read())
    except Exception:
        return {}


def check_traffic() -> None:
    quarantine = _fetch_quarantine()
    stats      = _fetch_stats()
    backend_up = bool(stats)

    info("\n" + "=" * 80 + "\n")
    info("  LIVE TRAFFIC STATUS\n")
    info("=" * 80 + "\n")
    if backend_up:
        info(f"  Backend: ONLINE  |  Threats: {stats.get('active_threats',0)}"
             f"  |  Dropped: {stats.get('malicious_dropped',0):,}"
             f"  |  FP rate: {stats.get('fp_rate',0.0):.1f}%\n")
    else:
        info("  Backend: OFFLINE\n")
    info("=" * 80 + "\n")
    info(f"  {'HOST':<6} {'IP':<14} {'SWITCH':<8} {'ROLE':<10} {'ATTACK TYPE':<12} STATUS\n")
    info("  " + "-" * 75 + "\n")

    for h in net.hosts:
        num         = int(h.name[1:])
        is_attacker = num in _ATTACKER_NUMS
        is_server   = num == 20
        ip          = h.IP()
        sw          = _host_switch_map.get(h.name, "?")

        if is_server:
            role, attack_type = "SERVER", "—"
            srv_up = h.cmd("pgrep -f 'http.server' 2>/dev/null").strip()
            status = "✓ HTTP running" if srv_up else "⚠ server down"
        elif is_attacker:
            role        = "ATTACKER"
            attack_type = next((f"[{a['attack_type']}] {a['flags']}"
                                for a in _attack_assignments if a["attacker"] == h.name), "?")
            hping_up = h.cmd("pgrep -x hping3 2>/dev/null").strip()
            mit      = quarantine.get(ip)
            if hping_up and mit:   status = f"★ ATTACKING → [{mit}]"
            elif hping_up:         status = "★ ATTACKING"
            elif mit:              status = f"⚡ MITIGATED [{mit}]"
            else:                  status = "— standby"
        else:
            role, attack_type = "legit", "—"
            mit     = quarantine.get(ip)
            t_alive = _baseline_threads.get(h.name)
            running = t_alive is not None and t_alive.is_alive()
            if mit:       status = f"⚠ FP? MITIGATED [{mit}]"
            elif running: status = "✓ baseline running"
            else:         status = "⚠ baseline stopped"

        info(f"  {h.name:<6} {ip:<14} {sw:<8} {role:<10} {attack_type:<12} {status}\n")

    info("=" * 80 + "\n\n")


# === AUTO-RESTORE ===

def restore_baseline_for_ip(src_ip: str) -> bool:
    # Restart baseline thread for a legit host released from quarantine
    for h in hosts:
        if h.IP() == src_ip and int(h.name[1:]) in _LEGIT_NUMS:
            if h.name in _baseline_stop:
                _baseline_stop[h.name].set()
            stop_ev = threading.Event()
            t = threading.Thread(
                target=_baseline_loop, args=(h, stop_ev),
                name=f"baseline-{h.name}", daemon=True
            )
            _baseline_stop[h.name]    = stop_ev
            _baseline_threads[h.name] = t
            t.start()
            _restore_log.info("Restored baseline for %s", src_ip)
            return True
    return False


def _restore_poller_loop() -> None:
    # Poll backend for IPs that need baseline restarted after quarantine release
    while True:
        time.sleep(RESTORE_POLL_S)
        try:
            with urllib.request.urlopen(f"{BACKEND_API}/api/pending_restores", timeout=3) as r:
                data = _json.loads(r.read())
            for ip in data.get("ips", []):
                restore_baseline_for_ip(ip)
        except Exception as e:
            _restore_log.debug("Restore poller error: %s", e)


def _baseline_watchdog_loop() -> None:
    # Every 30s restart any dead baseline threads
    while True:
        time.sleep(30)
        for h in hosts:
            if int(h.name[1:]) not in _LEGIT_NUMS:
                continue
            t = _baseline_threads.get(h.name)
            if t is None or not t.is_alive():
                restore_baseline_for_ip(h.IP())


def _start_restore_poller() -> None:
    threading.Thread(target=_restore_poller_loop, name="restore-poller", daemon=True).start()
    threading.Thread(target=_baseline_watchdog_loop, name="baseline-watchdog", daemon=True).start()
    info("*** Restore poller + watchdog started\n")


# === WATCH PIPELINE ===

def watch_pipeline(interval: float = 2.0, anomaly_only: bool = False, n: int = 20) -> None:
    # Print live ML pipeline scores — Ctrl+C to stop
    # Correct endpoint is /api/debug/flows
    url   = f"{BACKEND_API}/api/debug/flows"
    info("*** Pipeline viewer — Ctrl+C to stop\n\n")
    try:
        while True:
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    entries = _json.loads(r.read())  # returns list directly
                lines = ["\n  " + "=" * 90]
                lines.append(f"  LIVE ML PIPELINE — {len(entries)} entries")
                lines.append("  " + "=" * 90)
                lines.append(f"  {'TIME':<9} {'SRC_IP':<16} {'PPS':>8} {'IF_SCORE':>9}"
                             f" {'THR':>7} {'ANOMALY':>8} {'CLASS':<12} {'CONF%':>6} ACTION")
                lines.append("  " + "-" * 90)
                if not entries:
                    lines.append("  (waiting for traffic...)")
                for e in entries:
                    anom = "⚡ YES" if e.get("is_anomaly") else "  no"
                    lines.append(
                        f"  {e.get('ts','—'):<9} {e.get('src_ip','—'):<16}"
                        f" {e.get('pps',0):>8.1f} {e.get('if_score',0):>9.4f}"
                        f" {e.get('threshold',0):>7.4f} {anom:>8}"
                        f" {e.get('attack_class','—'):<12}"
                        f" {e.get('confidence',0):>6.1f}% {e.get('action','—')}"
                    )
                lines.append("  " + "=" * 90)
                info("\r" + "\n".join(lines) + "\n")
            except Exception as exc:
                info(f"  [backend offline: {exc}]\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        info("\n*** Viewer stopped.\n")


# === BANNER ===

def _print_banner(distribution: list, edge_switches: list) -> None:
    info("\n" + "=" * 75 + "\n")
    info("  A-DDoS Star Topology  |  1 core + 8 edge switches  |  20 hosts + h21\n")
    info(f"  Server:   h20 ({SERVER_IP}) — whitelisted, never ML-scored\n")
    info(f"  Sinkhole: h21 ({SINKHOLE_IP}) — silent dummy, redirected uncertain traffic\n")
    info("=" * 75 + "\n")
    info(f"  {'SWITCH':<8} {'HOSTS':<40} COUNT\n")
    info("  " + "-" * 60 + "\n")

    sw_hosts: dict[str, list] = {}
    for h in hosts:
        sw_hosts.setdefault(_host_switch_map.get(h.name, "?"), []).append(h)
    for sw_name in sorted(sw_hosts.keys()):
        h_list    = sw_hosts[sw_name]
        h_display = ", ".join(f"{h.name}({h.IP()})" for h in h_list)
        info(f"  {sw_name:<8} {h_display:<40} {len(h_list)}\n")

    info("\n" + "=" * 75 + "\n")
    info(f"  {'HOST':<6} {'IP':<14} {'ROLE':<10} ATTACK VARIANT\n")
    info("  " + "-" * 65 + "\n")
    for h in hosts:
        num = int(h.name[1:])
        if num == 20:
            role, atype = "SERVER", "— (whitelisted)"
        elif num == 21:
            role, atype = "SINKHOLE", "— (silent dummy)"
        elif num in _ATTACKER_NUMS:
            role  = "ATTACKER"
            atype = next((f"[{a['attack_type']}] {a['flags']}"
                          for a in _attack_assignments if a["attacker"] == h.name), "?")
        else:
            role, atype = "legit", "—"
        info(f"  {h.name:<6} {h.IP():<14} {role:<10} {atype}\n")

    info("\n" + "=" * 75 + "\n")
    info("  COMMANDS\n")
    info("  " + "-" * 65 + "\n")
    info("  ── BURST (finite) ────────────────────────────────────────────\n")
    info(f"  py launch_syn_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h1\n")
    info(f"  py launch_icmp_flood()                 # {ATTACK_PKT_COUNT:,} pkts, h7\n")
    info(f"  py launch_udp_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h11\n\n")
    info("  ── SUSTAINED (unlimited) ─────────────────────────────────────\n")
    info("  py launch_syn_flood_sustained()        # h1\n")
    info("  py launch_icmp_flood_sustained()       # h7\n")
    info("  py launch_udp_flood_sustained()        # h11\n\n")
    info("  ── ALL ATTACKERS ─────────────────────────────────────────────\n")
    info("  py launch_attack()                     # all 10, sustained\n")
    info("  py launch_attack(sustained=False)      # all 10, burst\n\n")
    info("  ── CAMPAIGNS ─────────────────────────────────────────────────\n")
    info("  py start_syn_flood_campaign()          # h1,h3,h5,h17\n")
    info("  py start_icmp_flood_campaign()         # h7,h9,h19\n")
    info("  py start_udp_flood_campaign()          # h11,h13,h15\n")
    info("  py start_mixed_campaign()              # all 10\n\n")
    info("  ── STOP ──────────────────────────────────────────────────────\n")
    info("  py stop_all_attacks()                  # kill + flush + clear\n")
    info("  py stop_baseline()                     # stop baseline\n\n")
    info("  ── OTHER ─────────────────────────────────────────────────────\n")
    info("  py flash_crowd()                       # 30s spike to server\n")
    info("  py flash_crowd(duration=60)            # custom duration\n")
    info("  py check_traffic()                     # live host status\n")
    info("  py watch_pipeline()                    # live ML scores\n")
    info("  py start_baseline_traffic()            # restart baseline\n")
    info("=" * 75 + "\n\n")


# === ENTRY POINT ===

if __name__ == "__main__":
    setLogLevel("info")

    net, hosts, edge_switches, distribution = build_star()
    net.start()
    _assign_attacks()

    # Wait for switches to connect to Ryu
    N_SWITCHES = 1 + N_EDGE
    info(f"*** Waiting for {N_SWITCHES} switches to connect to Ryu...\n")
    time.sleep(3)
    info(f"*** Switches ready — continuing.\n")

    _print_banner(distribution, edge_switches)
    _reset_ryu_state()
    start_server()
    _warmup_macs()

    info("*** Starting dynamic baseline traffic...\n")
    start_baseline_traffic()
    _start_restore_poller()
    info("*** Network ready — starting CLI.\n\n")

    # Build globals dict with net, hosts, and individual host shortcuts (h1, h2 ...)
    _g = globals().copy()
    _g["net"]   = net
    _g["hosts"] = hosts
    for _h in hosts:
        _g[_h.name] = _h

    class TopologyCLI(CLI):
        def do_py(self, line):
            try:
                result = eval(line, _g)
                if result is not None:
                    print(result)
            except SyntaxError:
                try:
                    exec(line, _g)
                except Exception as e:
                    print(f"Error: {e}")
            except Exception as e:
                print(f"Error: {e}")

    TopologyCLI(net)
    net.stop()