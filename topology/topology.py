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
    # SYN: no handshake = flows <1s, low bytes/pkt (~40-60B)
    6:  ("SYN",  "-S -p 80   --flood"),           # max pps, port 80
    7:  ("SYN",  "-S -p 443  --flood"),           # max pps, port 443
    8:  ("SYN",  "-S -p 8080 -i u10 --data 64"), # ~100k pps, small payload
    9:  ("SYN",  "-S -p 8443 -i u10 --data 128"),# ~100k pps, med payload
    19: ("SYN",  "-S -p 22   -i u10"),            # ~100k pps, header only
    # ICMP: flows 2-10s, bytes/pkt varies by --data
    10: ("ICMP", "--icmp --flood --data 1400"),    # max pps, large payload
    11: ("ICMP", "--icmp --flood --data 32"),      # max pps, small payload
    12: ("ICMP", "--icmp -i u10  --data 512"),     # ~100k pps, med payload
    13: ("ICMP", "--icmp -i u10  --data 256"),     # ~100k pps, small-med
    # UDP: flows 3-15s, high bytes/pkt
    14: ("UDP",  "--udp -p 53   --flood --data 1400"),  # max pps, DNS port
    15: ("UDP",  "--udp -p 80   --flood --data 1400"),  # max pps, HTTP port
    16: ("UDP",  "--udp -p 443  -i u10  --data 1024"),  # ~100k pps, HTTPS port
    17: ("UDP",  "--udp -p 123  -i u10  --data 512"),   # ~100k pps, NTP port
    18: ("UDP",  "--udp -p 1900 -i u10  --data 1400"),  # ~100k pps, SSDP port
}

# Staggered start delays per attacker (seconds) -- SYN wave first, ICMP mid, UDP last
# Simulates imperfect botnet coordination -- nodes do not all start simultaneously
_ATTACKER_START_DELAYS = {
    # SYN wave
    6:  0,
    7:  3,
    8:  5,
    9:  7,
    19: 9,
    # ICMP wave
    10: 14,
    11: 17,
    12: 20,
    13: 23,
    # UDP wave
    14: 28,
    15: 31,
    16: 34,
    17: 37,
    18: 40,
}

# Per-attacker cycle: (attack_min, attack_max, rest_min, rest_max) in seconds
# Based on real botnet behavior (Mirai, Bashlite) -- each node has different capacity
# Attack duration varies per cycle -- picked fresh each time from the range
_ATTACKER_CYCLES = {
    # SYN: short bursts -- real botnets send waves (20-60s attack, 5-15s rest)
    6:  (20, 60,  5, 15),
    7:  (25, 60,  5, 12),
    8:  (20, 50,  5, 12),
    9:  (20, 45,  5, 10),
    19: (20, 50,  5, 12),
    # ICMP: medium sustained (30-90s attack, 8-20s rest)
    10: (30, 90,  8, 20),
    11: (30, 80,  8, 18),
    12: (25, 70,  8, 18),
    13: (25, 60,  8, 15),
    # UDP: long sustained (60-120s attack, 10-25s rest)
    14: (60, 120, 10, 25),
    15: (60, 100, 10, 20),
    16: (60, 120, 12, 25),
    17: (60, 110, 10, 22),
    18: (60, 120, 10, 25),
}

# Global stop event for mixed campaign threads
_mixed_stop_event = threading.Event()
# Track active campaign threads
_campaign_threads: list = []

# h1-h2: ICMP only, h3-h4: TCP SYN, h5: UDP
# Max 5pps per host (min interval 0.2s)
# Each host has distinct rate range
_HOST_BASELINE_PROFILES = {
    1: {"idle": ((4.5, 5.5), (10, 30)), "active": ((0.8,  1.2),  (5, 15))},   # ICMP heartbeat ~1pps
    2: {"idle": ((4.0, 6.0), (10, 30)), "active": ((0.45, 0.55), (5, 15))},   # ICMP normal ping ~2pps
    3: {"idle": ((3.5, 4.5), (10, 30)), "active": ((1.8,  2.2),  (5, 12))},   # ICMP web browse ~0.5pps
    4: {"idle": ((4.0, 6.0), (10, 30)), "active": ((0.8,  1.2),  (5, 15))},   # ICMP ssh/api ~1pps
    5: {"idle": ((6.0, 10.0),(10, 30)), "active": ((3.5,  4.5),  (5, 12))},   # ICMP dns/ntp ~0.25pps
}

_DEFAULT_DURATIONS = {
    "idle": (10, 30), "active": (3, 12),
}

# Protocol per host — h1-h2 ICMP, h3-h4 TCP, h5 UDP
_HOST_PROTOCOL = {1: "icmp", 2: "icmp", 3: "tcp", 4: "tcp", 5: "udp"}
# Per-host ICMP variant — each legit host uses a distinct ping signature
# Varies by: payload size (-s), TTL (-t), IPv6 (ping6), flood type
# No two hosts share the same command template
_HOST_ICMP_VARIANT = {
    1: lambda ip, interval: f"ping -i {interval} -s 56  {ip}",
    2: lambda ip, interval: f"ping -i {interval} -s 56  {ip}",
    3: lambda ip, interval: f"ping -i {interval} -s 64  {ip}",
    4: lambda ip, interval: f"ping -i {interval} -s 56  {ip}",
    5: lambda ip, interval: f"ping -i {interval} -s 56  {ip}",
}

# Runtime state — populated at startup
_host_switch_map:    dict[str, str]              = {}
_attack_assignments: list[dict]                  = []
_active_attackers:   set[str]                    = set()  # IPs currently in attack phase
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


# Per-host TCP/UDP ports
_HOST_TCP_PORT = {3: 80, 4: 22}
_HOST_UDP_PORT = {5: 53}

# Fixed starting state — staggered
_HOST_START_STATE = {
    1: "active",
    2: "idle",
    3: "active",
    4: "idle",
    5: "active",
}

# Simple 2-state cycle: active -> idle -> active
_STATE_CYCLE = ["active", "idle"]


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
    num          = int(host.name[1:])
    profile      = _HOST_BASELINE_PROFILES.get(num)
    protocol     = _HOST_PROTOCOL.get(num, "icmp")

    start_state  = _HOST_START_STATE.get(num, "active")
    cycle_idx    = _STATE_CYCLE.index(start_state) if start_state in _STATE_CYCLE else 0

    while not stop_event.is_set():
        state_name = _STATE_CYCLE[cycle_idx % len(_STATE_CYCLE)]
        cycle_idx += 1

        if profile and state_name in profile:
            interval_range, duration_range = profile[state_name]
        else:
            interval_range = (1.0, 3.0)
            duration_range = _DEFAULT_DURATIONS.get(state_name, (10, 30))

        interval = round(random.uniform(*interval_range), 4)
        duration = random.randint(*duration_range)

        _kill_baseline_procs(host)

        # idle = very slow ICMP only (keep-alive), active = host protocol
        if state_name == "idle":
            _start_traffic(host, num, "icmp", round(random.uniform(2.0, 5.0), 4))
        else:
            _start_traffic(host, num, protocol, interval)

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


def _notify_attack_start(ip: str, attack_type: str) -> None:
    try:
        req = urllib.request.Request(
            f"{BACKEND_API}/api/attack_ground_truth/start",
            data=_json.dumps({"ip": ip, "attack_type": attack_type}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception:
        pass


def _notify_attack_stop(ip: str) -> None:
    _active_attackers.discard(ip)
    try:
        req = urllib.request.Request(
            f"{BACKEND_API}/api/attack_ground_truth/stop",
            data=_json.dumps({"ip": ip}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception:
        pass



def _attacker_cycle_worker(num: int, stop_event: threading.Event) -> None:
    h           = net.get(f"h{num}")
    delay       = _ATTACKER_START_DELAYS.get(num, 0)
    atk_min, atk_max, rst_min, rst_max = _ATTACKER_CYCLES.get(num, (15, 30, 5, 10))
    atype, _    = _ATTACKER_VARIANTS.get(num, ("SYN", ""))
    ip          = h.IP()

    for _ in range(delay):
        if stop_event.is_set():
            return
        time.sleep(1)

    while not stop_event.is_set():
        atk_dur = random.randint(atk_min, atk_max)
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        _notify_attack_start(ip, atype)
        _active_attackers.add(ip)

        for _ in range(atk_dur):
            if stop_event.is_set():
                _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)
                _notify_attack_stop(ip)
                return
            time.sleep(1)

        _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)
        _notify_attack_stop(ip)
        if stop_event.is_set():
            return

        rst_dur = random.randint(rst_min, rst_max)
        for _ in range(rst_dur):
            if stop_event.is_set():
                return
            time.sleep(1)

    _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)
    _notify_attack_stop(ip)
    _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)


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
    global _mixed_stop_event, _campaign_threads

    # 1. Signal threads to stop
    _mixed_stop_event.set()

    # 2. Join threads FIRST so no thread restarts hping3 after we kill it
    info("*** Waiting for campaign threads to exit...\n")
    for t in _campaign_threads:
        t.join(timeout=5)
    _campaign_threads.clear()

    # 3. Kill hping3 — wait=True so kill finishes before continuing
    info("*** Killing hping3 on all attackers...\n")
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)

    # 4. Force-kill stragglers
    time.sleep(0.3)
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            _nsrun(h, "pkill -9 -f hping3 2>/dev/null; true", wait=True)

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
    1: ("0.033", "~30 pps"),
    2: ("0.030", "~33 pps"),
    3: ("0.028", "~36 pps"),
    4: ("0.025", "~40 pps"),
    5: ("0.022", "~45 pps"),
}


def _flash_crowd_worker(legit: list, duration: int) -> None:
    # Properly stop baseline threads before starting flash crowd
    _stop_baseline_threads()

    # Kill any existing ping/hping3 and wait for processes to die
    for h in legit:
        _nsrun(h, "pkill -9 -f 'ping -i' 2>/dev/null; pkill -f hping3 2>/dev/null; true", wait=True)
    time.sleep(0.5)

    # Start flash crowd ping per host at elevated rate
    for h in legit:
        num = int(h.name[1:])
        interval, label = _FLASH_CROWD_PROFILES.get(num, ("0.050", "~20 pps"))
        _nsrun(h, f"ping -i {interval} {SERVER_IP} > /dev/null 2>&1")
        info(f"    {h.name} ({h.IP()}): {label} -> {SERVER_IP}\n")

    # Wait for duration -- background thread so CLI stays responsive
    time.sleep(duration)

    # Stop flash crowd ping — wait=True ensures ping is dead before baseline restores
    for h in legit:
        _nsrun(h, "pkill -9 -f 'ping -i' 2>/dev/null; true", wait=True)

    info("*** Flash crowd ended -- restoring baseline...\n")
    start_baseline_traffic()
    # Force new CLI prompt line
    import sys
    sys.stdout.write("mininet> ")
    sys.stdout.flush()


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

        if num == 21:
            role, attack_type = "SINKHOLE", "-"
            status = "✓ sinkhole active"
        elif is_server:
            role, attack_type = "SERVER", "-"
            srv_up = h.cmd("pgrep -f 'http.server' 2>/dev/null").strip()
            status = "✓ HTTP running" if srv_up else "⚠ server down"
        elif is_attacker:
            role        = "ATTACKER"
            attack_type = next((f"[{a['attack_type']}] {a['flags']}"
                                for a in _attack_assignments if a["attacker"] == h.name), "?")
            mit          = quarantine.get(ip)
            is_attacking = ip in _active_attackers
            if is_attacking and mit: status = f"★ ATTACKING -> [{mit}]"
            elif is_attacking:       status = "★ ATTACKING"
            elif mit:                status = f"⚡ MITIGATED [{mit}]"
            else:                    status = "standby"
        else:
            role, attack_type = "legit", "-"
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