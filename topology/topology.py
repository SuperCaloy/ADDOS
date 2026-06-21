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

# Network and backend config
CONTROLLER_IP    = "127.0.0.1"
CONTROLLER_PORT  = 6633
BACKEND_API      = "http://127.0.0.1:5000"
RESTORE_POLL_S   = 5.0
N_EDGE           = 8
N_HOSTS          = 20
SERVER_IP        = "10.0.0.20"   # h20, victim server
SINKHOLE_IP      = "10.0.0.21"   # h21, dummy sinkhole host
ATTACK_PKT_COUNT = 5000
WHITELIST_IPS    = {SERVER_IP, SINKHOLE_IP}

# h1 to h5 legit, h6 to h19 attacker
_ATTACKER_NUMS = {6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
_LEGIT_NUMS    = {1, 2, 3, 4, 5}

# 5 SYN, 5 ICMP, 2 UDP, 2 MIXED
_ATTACKER_VARIANTS = {
    6:  ("SYN", "-S -p 80   --flood"),
    7:  ("SYN", "-S -p 443  --flood"),
    8:  ("SYN", "-S -p 22   --flood"),
    9:  ("SYN", "-S -p 3306 --flood"),
    10: ("SYN", "-S -p 8080 --flood"),
    11: ("ICMP", "--icmp --flood --data 1400"),
    12: ("ICMP", "--icmp --flood --data 64"),
    13: ("ICMP", "--icmp --flood --data 256"),
    14: ("ICMP", "--icmp --flood --data 512"),
    15: ("ICMP", "--icmp --flood --data 128"),
    16: ("UDP", "--udp -p 53    --flood --data 1400"),
    17: ("UDP", "--udp -p 123   --flood --data 512"),
    # MIXED fires SYN and UDP together, model never trained on this combo
    18: ("MIXED", "-S -p 1900  --flood"),
    19: ("MIXED", "--udp -p 11211 --flood"),
}

# Stagger order: SYN, then ICMP, then UDP, then MIXED
_ATTACKER_START_DELAYS = {
    6: 0, 7: 2, 8: 4, 9: 6, 10: 8,
    11: 15, 12: 18, 13: 21, 14: 24, 15: 27,
    16: 32, 17: 35, 18: 38, 19: 41,
}

# attack_min, attack_max, rest_min, rest_max in seconds
_ATTACKER_CYCLES = {
    6:  (5, 20, 2, 8),
    7:  (5, 18, 2, 7),
    8:  (6, 20, 2, 8),
    9:  (5, 15, 2, 6),
    10: (6, 18, 2, 7),
    11: (30, 90,  8, 20),
    12: (35, 90,  8, 18),
    13: (25, 80,  8, 18),
    14: (30, 75,  8, 15),
    15: (25, 70,  8, 15),
    16: (10, 30, 5, 15),
    17: (10, 28, 5, 12),
    18: (12, 30, 5, 15),
    19: (10, 25, 5, 12),
}

_mixed_stop_event = threading.Event()
_campaign_threads: list = []

# size_min, size_max, sleep_min, sleep_max
_ICMP_CONTINUOUS = {
    0: (42, 56, 4.5, 6.0),
    1: (42, 56, 3.5, 4.5),
    3: (42, 56, 3.5, 4.5),
}

# port: size_min, size_max, sleep_min, sleep_max
_TCP_PROFILES = {
    80:   (64, 512, 2.0, 5.0),
    443:  (64, 512, 2.0, 5.0),
    8080: (64, 512, 2.0, 5.0),
}

# port: size_min, size_max, sleep_min, sleep_max
_UDP_PROFILES = {
    53:   (64, 512, 2.0, 5.0),
    123:  (64, 512, 2.0, 5.0),
    1900: (64, 512, 2.0, 5.0),
}

# host slot pools, picked randomly each active cycle
# TCP heavy, UDP moderate, ICMP light, matches real traffic
_HOST_SLOTS = {
    1: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    2: [("tcp", 80), ("tcp", 443), ("tcp", 8080)],
    3: [("udp", 53), ("udp", 123), ("udp", 1900)],
    4: [("udp", 53), ("udp", 123), ("udp", 1900)],
    5: [("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3)],
}

# full slot pool used after idle, for random type switch
_ALL_SLOTS = [
    ("icmp_cont", 0), ("icmp_cont", 1), ("icmp_cont", 3),
    ("tcp", 80), ("tcp", 443), ("tcp", 8080),
    ("udp", 53), ("udp", 123), ("udp", 1900),
]

_DEFAULT_DURATIONS = {
    "idle":   (3, 5),
    "active": (60, 60),
}

# Runtime state, set at startup
_host_switch_map:    dict[str, str]              = {}
_attack_assignments: list[dict]                  = []
_active_attackers:   set[str]                    = set()
_baseline_threads:   dict[str, threading.Thread] = {}
_baseline_stop:      dict[str, threading.Event]  = {}
_idle_host_ref:      list = [-1]
_restore_log = _logging.getLogger("restore_poller")

net   = None
hosts = []


# === TOPOLOGY ===

def _weighted_distribute(n_hosts: int, n_switches: int) -> list[int]:
    # spread hosts across switches, weighted toward 1-2 per switch
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
    # 1 core switch, n_edge switches, hosts on flat 10.0.0.x/24
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

    # h21 is a silent sinkhole host, connected to core, receives redirected traffic
    sinkhole = _net.addHost(
        "h21",
        ip=f"{SINKHOLE_IP}/24",
        mac="00:00:00:00:00:15",
    )
    _net.addLink(sinkhole, core)
    _host_switch_map["h21"] = core.name

    return _net, _hosts, edge_switches, distribution


def _assign_attacks() -> list[dict]:
    # map each attacker host to its fixed hping3 variant
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

def _kill_baseline_procs(host) -> None:
    # kill ping and hping3 inside host netns
    for proc in ("ping", "hping3"):
        subprocess.run(
            f"nsenter -t {host.pid} -n -- pkill -9 -x {proc} || true",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


def _nsrun(host, cmd: str, wait: bool = False) -> None:
    # run a command inside host netns
    full = f"nsenter -t {host.pid} -n -- bash -c {cmd!r}"
    if wait:
        subprocess.run(full, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(full, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


_HOST_START_STATE = {1: "active", 2: "active", 3: "active", 4: "active", 5: "active"}
_STATE_CYCLE = ["active", "idle"]
_idle_slot = threading.Semaphore(1)


def _kill_attacker(host) -> None:
    # kill hping3 inside host pid namespace, regardless of who launched it
    subprocess.run(
        f"nsenter -t {host.pid} -n -p -- pkill -9 -x hping3 2>/dev/null; true",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def _write_slot_script(slot_type: str, slot_key: int, size: int, dst: str) -> str:
    path = f"/tmp/slot_{slot_type}_{slot_key}.py"
    if slot_type == "tcp":
        code = (
            f"import socket,os\n"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            f"s.settimeout(3)\n"
            f"s.connect(('{dst}',{slot_key}))\n"
            f"s.sendall(os.urandom({size}))\n"
            f"s.close()\n"
        )
    else:
        code = (
            f"import socket,os\n"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            f"s.sendto(os.urandom({size}),('{dst}',{slot_key}))\n"
            f"s.close()\n"
        )
    with open(path, "w") as f:
        f.write(code)
    return path


def _run_slot(host, slot_type: str, slot_key: int) -> None:
    if slot_type == "icmp_cont":
        p     = _ICMP_CONTINUOUS[slot_key]
        size  = random.randint(p[0], p[1])
        sleep = round(random.uniform(p[2], p[3]), 4)
        _nsrun(host, f"ping -i {sleep} -s {size} {SERVER_IP} > /dev/null 2>&1")
    elif slot_type == "tcp":
        p      = _TCP_PROFILES[slot_key]
        size   = random.randint(p[0], p[1])
        script = _write_slot_script("tcp", slot_key, size, SERVER_IP)
        _nsrun(host, f"python3 {script} > /dev/null 2>&1")
    elif slot_type == "udp":
        p      = _UDP_PROFILES[slot_key]
        size   = random.randint(p[0], p[1])
        script = _write_slot_script("udp", slot_key, size, SERVER_IP)
        _nsrun(host, f"python3 {script} > /dev/null 2>&1")

def _baseline_loop(host, stop_event: threading.Event, idle_host_ref: list) -> None:
    num   = int(host.name[1:])
    slots = list(_HOST_SLOTS.get(num, [("icmp_cont", 1)]))

    while not stop_event.is_set():
        # check if this host is chosen to idle
        if idle_host_ref[0] == num:
            _kill_baseline_procs(host)
            idle_dur = random.randint(*_DEFAULT_DURATIONS["idle"])
            end_idle = time.time() + idle_dur
            while not stop_event.is_set() and time.time() < end_idle:
                time.sleep(1)
            # pick a new random slot type after idle
            slots = [random.choice(_ALL_SLOTS)]
            idle_host_ref[0] = -1
            continue

        # active phase, send every 2-5s for 60s
        end_active = time.time() + 60
        while not stop_event.is_set() and time.time() < end_active:
            if idle_host_ref[0] == num:
                break
            slot_type, slot_key = random.choice(slots)
            _run_slot(host, slot_type, slot_key)
            time.sleep(random.uniform(2.0, 5.0))

    _kill_baseline_procs(host)

def start_baseline_traffic() -> None:
    # start a baseline thread for every legit host
    global _baseline_threads, _baseline_stop
    _stop_baseline_threads()
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
    info(f"*** Starting baseline on {len(legit)} legit hosts -> {SERVER_IP}\n")

    # shared ref, which host num is currently idling, -1 means none
    idle_host_ref = _idle_host_ref
    idle_host_ref[0] = -1
    legit_nums    = [int(h.name[1:]) for h in legit]

    def _idle_rotator(stop_ev):
        while not stop_ev.is_set():
            time.sleep(60)
            if stop_ev.is_set():
                break
            idle_host_ref[0] = random.choice(legit_nums)

    stop_rot = threading.Event()
    rot = threading.Thread(target=_idle_rotator, args=(stop_rot,), daemon=True)
    rot.start()

    for host in legit:
        stop_ev = threading.Event()
        t = threading.Thread(
            target=_baseline_loop, args=(host, stop_ev, idle_host_ref),
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
    # raw L4 TCP and UDP listeners on h20
    server = net.get("h20")
    server.cmd("pkill -f 'tcp_udp_server' 2>/dev/null; pkill -f 'http.server' 2>/dev/null; true")
    server.cmd(
        "python3 -c \""
        "import socket,threading,os\n"
        "def tcp(port):\n"
        " s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        " s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        " s.bind(('0.0.0.0',port));s.listen(100)\n"
        " while True:\n"
        "  c,_=s.accept();threading.Thread(target=lambda c:c.recv(4096) and c.close(),args=(c,),daemon=True).start()\n"
        "def udp(port):\n"
        " s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        " s.bind(('0.0.0.0',port))\n"
        " while True: s.recvfrom(4096)\n"
        "for p in [80,443,8080]:\n"
        " threading.Thread(target=tcp,args=(p,),daemon=True).start()\n"
        "for p in [53,123,1900]:\n"
        " threading.Thread(target=udp,args=(p,),daemon=True).start()\n"
        "import time\n"
        "while True: time.sleep(60)\n"
        "\" > /dev/null 2>&1 &"
    )
    info(f"*** Raw L4 server started on h20 ({SERVER_IP}) TCP:80,443,8080 UDP:53,123,1900\n")


# === ATTACKS ===

def _hping_cmd(attacker_num: int, target: str, count: int = None) -> str:
    # build hping3 command from attacker variant config
    atype, flags = _ATTACKER_VARIANTS.get(attacker_num, ("SYN", "-S -p 80 --flood"))
    count_flag   = f"-c {count} " if count else ""

    if atype == "MIXED":
        # fire SYN and UDP together, one source IP, two protocols
        return (f"hping3 -S -p 1900 {count_flag}{target} 2>/dev/null & "
                f"hping3 --udp -p 11211 {count_flag}{target} 2>/dev/null &")

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
    h      = net.get(f"h{num}")
    delay  = _ATTACKER_START_DELAYS.get(num, 0)
    atk_min, atk_max, rst_min, rst_max = _ATTACKER_CYCLES.get(num, (15, 30, 5, 10))
    ip     = h.IP()

    for _ in range(delay):
        if stop_event.is_set():
            return
        time.sleep(1)

    while not stop_event.is_set():
        atype, _ = _ATTACKER_VARIANTS.get(num, ("SYN", ""))
        cmd      = _hping_cmd(num, SERVER_IP)

        atk_dur = random.randint(atk_min, atk_max)
        _nsrun(h, f"{cmd} > /dev/null 2>&1")
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
    # launch all attackers at once, no stagger, no cycles
    # use start_mixed_campaign() for staggered cyclic behavior
    global _mixed_stop_event, _campaign_threads
    _mixed_stop_event.clear()
    count = None if sustained else ATTACK_PKT_COUNT
    info(f"*** {'Sustained' if sustained else 'Burst'} DDoS, all attackers -> {SERVER_IP}\n\n")
    for a in _attack_assignments:
        num      = int(a["attacker"][1:])
        attacker = net.get(a["attacker"])
        cmd      = _hping_cmd(num, SERVER_IP, count)
        info(f"    {a['attacker']} ({attacker.IP()})  [{a['attack_type']}] {a['flags']}\n")
        _nsrun(attacker, f"{cmd} > /dev/null 2>&1")
    info("\n    -> Use  py stop_all_attacks()  to stop.\n")


def launch_syn_flood(attacker_name="h6") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** SYN burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_icmp_flood(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** ICMP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_udp_flood(attacker_name="h16") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** UDP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_syn_flood_sustained(attacker_name="h6") -> None:
    attacker = net.get(attacker_name)
    info(f"*** SYN sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def launch_icmp_flood_sustained(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    info(f"*** ICMP sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def launch_udp_flood_sustained(attacker_name="h16") -> None:
    attacker = net.get(attacker_name)
    info(f"*** UDP sustained: {attacker_name} -> {SERVER_IP}\n")
    _nsrun(attacker, f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1")


def start_syn_flood_campaign() -> None:
    info("*** [CAMPAIGN] SYN, h6 h7 h8\n")
    for num in [6, 7, 8]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> use  py stop_all_attacks()  to stop.\n")


def start_icmp_flood_campaign() -> None:
    info("*** [CAMPAIGN] ICMP, h11 h12 h13\n")
    for num in [11, 12, 13]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> use  py stop_all_attacks()  to stop.\n")


def start_udp_flood_campaign() -> None:
    info("*** [CAMPAIGN] UDP, h16 h17 h18\n")
    for num in [16, 17, 18]:
        h = net.get(f"h{num}")
        _nsrun(h, f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    -> use  py stop_all_attacks()  to stop.\n")


def start_mixed_campaign() -> None:
    # all attackers, staggered starts, independent random attack/rest cycles
    global _mixed_stop_event, _campaign_threads
    _mixed_stop_event.clear()
    _campaign_threads.clear()

    info("*** [CAMPAIGN] Mixed, staggered cyclic attack, all 14 attackers\n")
    info("    SYN (h6-h10) -> ICMP (h11-h15) -> UDP (h16-h17) -> MIXED (h18-h19)\n")
    info("    Each attacker runs a random attack and rest cycle until stopped\n\n")

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

    info("\n    -> use  py stop_all_attacks()  to stop.\n")


def stop_all_attacks() -> None:
    global _mixed_stop_event, _campaign_threads

    # signal threads to stop
    _mixed_stop_event.set()

    # join threads first, so no thread restarts hping3 after we kill it
    info("*** Waiting for campaign threads to exit...\n")
    for t in _campaign_threads:
        t.join(timeout=5)
    _campaign_threads.clear()

    # kill hping3, wait for it to finish before continuing
    info("*** Killing hping3 on all attackers...\n")
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            _nsrun(h, "pkill -f hping3 2>/dev/null; true", wait=True)

    # force kill stragglers
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
        # invalidate cache for one IP, runs in its own thread
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

    # run all cache invalidations in parallel
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

    info("*** Attack stopped, forwarding restored.\n")


# === FLASH CROWD ===

# flash crowd, elevated rate per host, same traffic type as baseline
# pkt_min, pkt_max, sleep_min, sleep_max, faster than baseline profiles
_FLASH_CROWD_PROFILES = {
    1: ("icmp_cont", 56,  64,  0.8, 1.2),
    2: ("icmp_cont", 56,  64,  0.8, 1.2),
    3: ("tcp",       80,  20,  50,  0.5, 1.0),
    4: ("tcp",       443, 20,  60,  0.5, 1.0),
    5: ("udp",       53,  5,   10,  0.8, 1.5),
}


def _flash_crowd_run_slot(host, num: int) -> None:
    profile = _FLASH_CROWD_PROFILES.get(num)
    if not profile:
        return
    kind = profile[0]
    if kind == "icmp_cont":
        _, size_min, size_max, slp_min, slp_max = profile
        size  = random.randint(size_min, size_max)
        sleep = round(random.uniform(slp_min, slp_max), 4)
        _nsrun(host, f"ping -i {sleep} -s {size} {SERVER_IP} > /dev/null 2>&1")
    elif kind == "tcp":
        # raw L4 TCP, full handshake plus random bytes
        _, port, pkt_min, pkt_max, slp_min, slp_max = profile
        size = random.randint(pkt_min, pkt_max)
        _nsrun(host, (
            f"python3 -c \""
            f"import socket,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.settimeout(3);"
            f"s.connect(('{SERVER_IP}',{port}));"
            f"s.sendall(os.urandom({size}));"
            f"s.close()"
            f"\" 2>/dev/null"
        ))
    elif kind == "udp":
        # raw L4 UDP, sendto random bytes
        _, port, pkt_min, pkt_max, slp_min, slp_max = profile
        size = random.randint(pkt_min, pkt_max)
        _nsrun(host, (
            f"python3 -c \""
            f"import socket,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            f"s.sendto(os.urandom({size}),('{SERVER_IP}',{port}));"
            f"s.close()"
            f"\" 2>/dev/null"
        ))


def _flash_crowd_worker(legit: list, duration: int) -> None:
    _stop_baseline_threads()

    for h in legit:
        _nsrun(h, "pkill -9 -f 'ping -i' 2>/dev/null; pkill -f hping3 2>/dev/null; true", wait=True)
    time.sleep(0.5)

    for h in legit:
        num = int(h.name[1:])
        _flash_crowd_run_slot(h, num)
        info(f"    {h.name} ({h.IP()}): flash crowd -> {SERVER_IP}\n")

    time.sleep(duration)

    for h in legit:
        _nsrun(h, "pkill -9 -f 'ping -i' 2>/dev/null; pkill -f hping3 2>/dev/null; true", wait=True)

    info("*** Flash crowd ended, restoring baseline...\n")
    start_baseline_traffic()
    import sys
    sys.stdout.write("mininet> ")
    sys.stdout.flush()


def flash_crowd(duration: int = 30) -> None:
    # all legit hosts spike to server, simulates a viral or ticket sale event
    # runs in background, CLI stays responsive, baseline restores after duration
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
    info(f"*** Flash crowd, {len(legit)} legit hosts -> {SERVER_IP} for {duration}s\n")
    info(f"    CLI active, baseline restores automatically after {duration}s\n\n")
    threading.Thread(
        target=_flash_crowd_worker, args=(legit, duration),
        name="flash-crowd", daemon=True
    ).start()


# === WARMUP ===

def _reset_ryu_state() -> None:
    # send reset to Ryu via ZMQ, clears banned_ips, mac table, ip_to_dpid, counters
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
    # install FLOOD rules so warmup pings bypass Ryu, avoids packet-in surge
    info("*** Warmup, installing FLOOD rules, Ryu bypassed...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl add-flow {sw.name} priority=0,actions=FLOOD",
                       shell=True, capture_output=True)

    # each legit host pings server once in parallel, just to populate ARP
    info("*** Pinging server in parallel to populate MAC tables...\n")
    legit = [h for h in hosts if int(h.name[1:]) not in _ATTACKER_NUMS]
    for src in legit:
        _nsrun(src, f"ping -c1 -W1 {SERVER_IP} > /dev/null 2>&1")
    time.sleep(2)

    info("*** Removing FLOOD rules, Ryu resuming control...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl del-flows {sw.name} priority=0",
                       shell=True, capture_output=True)

    info("*** Waiting 3s for flows to age...\n")
    time.sleep(3)

    # clear prefilter flags, warmup pings accumulate burst counts
    # without this, legit hosts trip flood prefilter on first baseline ping
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from backend.pipeline.flood_prefilter import flood_filter as _ff
    for h in hosts:
        if int(h.name[1:]) not in _ATTACKER_NUMS:
            _ff.clear_flag(h.IP())
    info("*** Prefilter flags cleared for legit hosts.\n")

    # signal Ryu to start forwarding stats to backend
    try:
        import zmq as _zmq
        _ctx  = _zmq.Context.instance()
        _sock = _ctx.socket(_zmq.PUSH)
        _sock.setsockopt(_zmq.LINGER, 0)
        _sock.setsockopt(_zmq.SNDTIMEO, 500)
        _sock.connect("tcp://127.0.0.1:5556")
        _sock.send_json({"action": "warmup_done"})
        _sock.close()
    except Exception as e:
        info(f"    warmup_done warning: {e}\n")

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
            srv_up = h.cmd("pgrep -f 'tcp_udp_server\\|time.sleep' 2>/dev/null").strip()
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
    # restart baseline thread for a legit host released from quarantine
    for h in hosts:
        if h.IP() == src_ip and int(h.name[1:]) in _LEGIT_NUMS:
            if h.name in _baseline_stop:
                _baseline_stop[h.name].set()
            stop_ev = threading.Event()
            t = threading.Thread(
                target=_baseline_loop, args=(h, stop_ev, _idle_host_ref),
                name=f"baseline-{h.name}", daemon=True
            )
            _baseline_stop[h.name]    = stop_ev
            _baseline_threads[h.name] = t
            t.start()
            _restore_log.info("Restored baseline for %s", src_ip)
            return True
    return False


def _restore_poller_loop() -> None:
    # poll backend for IPs that need baseline restarted after quarantine release
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
    # every 30s, restart any dead baseline threads
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
    # print live ML pipeline scores, Ctrl+C to stop
    url   = f"{BACKEND_API}/api/debug/flows"
    info("*** Pipeline viewer, Ctrl+C to stop\n\n")
    try:
        while True:
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    entries = _json.loads(r.read())
                lines = ["\n  " + "=" * 90]
                lines.append(f"  LIVE ML PIPELINE, {len(entries)} entries")
                lines.append("  " + "=" * 90)
                lines.append(f"  {'TIME':<9} {'SRC_IP':<16} {'PPS':>8} {'IF_SCORE':>9}"
                             f" {'THR':>7} {'ANOMALY':>8} {'CLASS':<12} {'CONF%':>6} ACTION")
                lines.append("  " + "-" * 90)
                if not entries:
                    lines.append("  (waiting for traffic...)")
                for e in entries:
                    anom = "⚡ YES" if e.get("is_anomaly") else "  no"
                    lines.append(
                        f"  {e.get('ts','-'):<9} {e.get('src_ip','-'):<16}"
                        f" {e.get('pps',0):>8.1f} {e.get('if_score',0):>9.4f}"
                        f" {e.get('threshold',0):>7.4f} {anom:>8}"
                        f" {e.get('attack_class','-'):<12}"
                        f" {e.get('confidence',0):>6.1f}% {e.get('action','-')}"
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
    info(f"  Server:   h20 ({SERVER_IP}) - whitelisted, never ML-scored\n")
    info(f"  Sinkhole: h21 ({SINKHOLE_IP}) - silent dummy, redirected uncertain traffic\n")
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
            role, atype = "SERVER", "(whitelisted)"
        elif num == 21:
            role, atype = "SINKHOLE", "(silent dummy)"
        elif num in _ATTACKER_NUMS:
            role  = "ATTACKER"
            atype = next((f"[{a['attack_type']}] {a['flags']}"
                          for a in _attack_assignments if a["attacker"] == h.name), "?")
        else:
            role, atype = "legit", "-"
        info(f"  {h.name:<6} {h.IP():<14} {role:<10} {atype}\n")

    info("\n" + "=" * 75 + "\n")
    info("  COMMANDS\n")
    info("  " + "-" * 65 + "\n")
    info("  ── BURST (finite) ────────────────────────────────────────────\n")
    info(f"  py launch_syn_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h6\n")
    info(f"  py launch_icmp_flood()                 # {ATTACK_PKT_COUNT:,} pkts, h11\n")
    info(f"  py launch_udp_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h16\n\n")
    info("  ── SUSTAINED (unlimited) ─────────────────────────────────────\n")
    info("  py launch_syn_flood_sustained()        # h6\n")
    info("  py launch_icmp_flood_sustained()       # h11\n")
    info("  py launch_udp_flood_sustained()        # h16\n\n")
    info("  ── ALL ATTACKERS ─────────────────────────────────────────────\n")
    info("  py launch_attack()                     # all 14, sustained\n")
    info("  py launch_attack(sustained=False)      # all 14, burst\n\n")
    info("  ── CAMPAIGNS ─────────────────────────────────────────────────\n")
    info("  py start_syn_flood_campaign()          # h6,h7,h8\n")
    info("  py start_icmp_flood_campaign()         # h11,h12,h13\n")
    info("  py start_udp_flood_campaign()          # h16,h17,h18\n")
    info("  py start_mixed_campaign()              # all 14, staggered cyclic\n\n")
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

    # wait for switches to connect to Ryu
    N_SWITCHES = 1 + N_EDGE
    info(f"*** Waiting for {N_SWITCHES} switches to connect to Ryu...\n")
    time.sleep(3)
    info(f"*** Switches ready, continuing.\n")

    _print_banner(distribution, edge_switches)
    _reset_ryu_state()
    start_server()
    _warmup_macs()

    info("*** Starting dynamic baseline traffic...\n")
    start_baseline_traffic()
    _start_restore_poller()
    info("*** Network ready, starting CLI.\n\n")

    # build globals dict with net, hosts, and host shortcuts like h1, h2
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