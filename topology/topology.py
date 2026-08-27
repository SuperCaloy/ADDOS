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
N_HOSTS          = 27
SERVER_IP        = "10.0.0.20"   # h20, victim server
SINKHOLE_IP      = "10.0.0.21"   # h21, dummy sinkhole host
ATTACK_PKT_COUNT = 5000
WHITELIST_IPS    = {SERVER_IP, SINKHOLE_IP}

# h1 to h5 legit; 15 attackers (h6-h18 + h22,h23; h16/h22 repurposed SYN,
# 2026-08-26); h20 server; h21 sinkhole; retired silent hosts h19,h24-h27
# (built but never launch, never baseline). Rollback to 20 attackers =
# set _RETIRED_NUMS to empty.
_LEGIT_NUMS    = frozenset({1, 2, 3, 4, 5})
_RETIRED_NUMS  = frozenset({19, 24, 25, 26, 27})
_ATTACKER_NUMS = frozenset(
    n for n in (*range(6, 20), *range(22, 28)) if n not in _RETIRED_NUMS)
# pool = attackers + retired: CLEANUP sweeps cover both so a hand-launched
# retired host can still be fully stopped; launch paths stay active-only
_ATTACKER_POOL = _ATTACKER_NUMS | _RETIRED_NUMS

# 5 SYN, 5 ICMP, 5 UDP (balanced; h16 repurposed to SYN/5432, h22 to
# SYN/3389). Attack variants: --flood keeps the send dynamics the operator
# wants; payload sizes are capped at 512-800 data bytes so flood bandwidth
# stays at or below the original smooth baseline while every attack row
# still sits outside the normal 70-300B size band (wire >= 540B).
_ALL_VARIANTS = {
    6:  ("UDP",  "--udp -p 53    --flood --data 512",  0, 0),
    7:  ("UDP",  "--udp -p 123   --flood --data 512",  0, 0),
    8:  ("UDP",  "--udp -p 1900  --flood --data 512",  0, 0),
    9:  ("UDP",  "--udp -p 11211 --flood --data 800",  0, 0),
    10: ("SYN",  "-S -p 8080 --flood",                 0, 0),
    11: ("ICMP", "--icmp --flood --data 800",          0, 0),
    12: ("ICMP", "--icmp --flood --data 800",          0, 0),
    13: ("ICMP", "--icmp --flood --data 800",          0, 0),
    14: ("ICMP", "--icmp --flood --data 800",          0, 0),
    15: ("ICMP", "--icmp --flood --data 512",          0, 0),
    16: ("SYN",  "-S -p 5432 --flood",                 0, 0),
    17: ("UDP",  "--udp -p 123   --flood --data 800",  0, 0),
    18: ("SYN",  "-S -p 1900   --flood",               0, 0),
    19: ("SYN",  "-S -p 1900   --flood",               0, 0),  # retired
    22: ("SYN",  "-S -p 3389 --flood",                 0, 0),
    23: ("SYN",  "-S -p 25   --flood",                 0, 0),
    24: ("SYN",  "-S -p 3389 --flood",                 0, 0),  # retired
    25: ("SYN",  "-S -p 5432 --flood",                 0, 0),  # retired
    26: ("ICMP", "--icmp --flood --data 512",          0, 0),  # retired
    27: ("ICMP", "--icmp --flood --data 800",          0, 0),  # retired
}
_ATTACKER_VARIANTS = {n: v for n, v in _ALL_VARIANTS.items()
                      if n in _ATTACKER_NUMS}
assert set(_ATTACKER_VARIANTS) == set(_ATTACKER_NUMS)

# rand-source stress commands are GENERATED from _ATTACKER_VARIANTS so sizes
# and flags can never drift between the two families; spoofing is a separate
# memory-stress metric and stays expressed here as the extra flag.
_STRESS_CMDS = {}
for _n, (_t, _fl, _, _) in _ATTACKER_VARIANTS.items():
    if _t == "SYN":
        _core = f"{_fl} --rand-source"
    else:
        _core = _fl.replace("--data ", "--rand-source --data ", 1)
    _STRESS_CMDS[_n] = f"hping3 {_core} {SERVER_IP} > /dev/null 2>&1"
del _n, _t, _fl

# Stagger delays: 0.5-2.0s random
_ATTACKER_START_DELAYS = {
    num: round(random.uniform(0.1, 0.6), 2) for num in _ATTACKER_NUMS
}

# attack_min, attack_max, rest_min, rest_max in seconds
# (dead _ATTACKER_CYCLES dict removed 2026-08-26: defined once, never read
# by any code path; all attackers run pure continuous --flood)

_mixed_stop_event = threading.Event()
_campaign_threads: list = []

# size_min, size_max, sleep_min, sleep_max
_ICMP_CONTINUOUS = {
    0: (56, 56,  4.5,  6.0),
    1: (56, 56, 10.0, 15.0),
    3: (56, 56,  3.5,  4.5),
}

# port: size_min, size_max, sleep_min, sleep_max
_TCP_PROFILES = {
    80:   (64, 256, 3.0, 6.0),
    443:  (64, 256, 3.0, 6.0),
    8080: (64, 256, 3.0, 6.0),
}

# port: size_min, size_max, sleep_min, sleep_max
_UDP_PROFILES = {
    53:   (64, 256, 3.0, 6.0),
    123:  (64, 256, 4.0, 8.0),
    1900: (64, 256, 3.0, 6.0),
}

# host slot pools, picked randomly each active cycle. These are the exact
# trained signatures: a normal-side diversity experiment (cross-type slots,
# timing mixtures, mesh pings) was REVERTED after it produced a 10.23 pct
# live false-positive rate against the frozen model, which only recognizes
# the old capture's normality as normal.
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
    "idle":   (5, 15),
    "active": (45, 45),
}

# Runtime state, set at startup
_host_switch_map:    dict[str, str]              = {}
_attack_assignments: list[dict]                  = []
_active_attackers:   set[str]                    = set()
# per-IP campaign start times: lets stop posts carry a cutoff so a stranded
# stop can never delete a newer campaign's ground-truth entry (Round 5 S8)
_attack_started_at:  dict[str, float]            = {}
_baseline_threads:   dict[str, threading.Thread] = {}
_baseline_stop:      dict[str, threading.Event]  = {}
_baseline_lock       = threading.Lock()
# live Popen handles of baseline slot launches per host, drained by
# _kill_baseline_procs so cleanup kills exact pids instead of pattern
# matching /proc globally
_baseline_slot_procs: dict[str, list] = {}
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
    # 1 core switch, n_edge switches, hosts on flat 10.0.0.x/24.
    # Layout is fixed — not random — so topology is identical every run:
    #   s1–s7 → h1–h19 + h22–h24 evenly spread (2–4 hosts each)
    #   s8    → h20 server only (dedicated, isolated from attacker switches)
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

    # Fixed host-to-switch mapping — deterministic every run.
    # h1-h19 + h22-h27 spread across s1-s7 (3-4 per switch). Note: hosts
    # h19,h24-h27 are RETIRED (built, silent) since the 15-attacker cut.
    # h20 server on s8 only — dedicated, no attacker on same switch.
    # h21 is the sinkhole, added separately below, skipped in this loop.
    _HOST_TO_SWITCH = {
        1: 1,  2: 1,  3: 1,  22: 1,
        4: 2,  5: 2,  6: 2,  23: 2,
        7: 3,  8: 3,  9: 3,  24: 3,
        10: 4, 11: 4, 12: 4, 25: 4,
        13: 5, 14: 5, 15: 5, 26: 5,
        16: 6, 17: 6, 18: 6, 27: 6,
        19: 7,
        20: 8,
    }

    _hosts = []
    for host_num in range(1, n_hosts + 1):
        if host_num == 21:
            continue  # reserved for sinkhole, added separately below
        sw_idx = _HOST_TO_SWITCH[host_num]
        sw     = edge_switches[sw_idx - 1]
        ip     = f"10.0.0.{host_num}"
        mac    = f"00:00:00:00:00:{host_num:02x}"
        host   = _net.addHost(f"h{host_num}", ip=f"{ip}/24", mac=mac)
        _net.addLink(host, sw)
        _hosts.append(host)
        _host_switch_map[f"h{host_num}"] = sw.name

    # Distribution count per switch — dead value, never read:
    # _print_banner computes the live table from _host_switch_map
    distribution = [5, 5, 5, 5, 5, 5, 5, 1]

    # h21 silent sinkhole — connected to core, receives redirected traffic
    sinkhole = _net.addHost(
        "h21",
        ip=f"{SINKHOLE_IP}/24",
        mac="00:00:00:00:00:15",
    )
    _net.addLink(sinkhole, core)
    _host_switch_map["h21"] = core.name

    return _net, _hosts, edge_switches, distribution


def _speed_up_reconnect(edge_switches, core) -> None:
    # Lower OVS inactivity probe + backoff so dead controller connections
    # are detected and retried fast instead of default ~15-25s.
    for sw in [core] + edge_switches:
        subprocess.run(
            f"ovs-vsctl set controller {sw.name} "
            f"inactivity_probe=5000 max_backoff=2000",
            shell=True
        )


def _assign_attacks() -> list[dict]:
    # map each attacker host to its fixed hping3 variant
    global _attack_assignments
    _attack_assignments = []
    for h in hosts:
        num = int(h.name[1:])
        if num in _ATTACKER_NUMS:
            attack_type, flags, _, _ = _ATTACKER_VARIANTS[num]
            _attack_assignments.append({
                "attacker": h.name, "attack_type": attack_type,
                "flags": flags, "target": SERVER_IP,
            })
    return _attack_assignments


# === BASELINE TRAFFIC ===

def _kill_baseline_procs(host) -> None:
    # SIGKILL exactly this host's tracked baseline processes. The old global
    # pkill walked /proc across ALL hosts (Mininet hosts share the root pid
    # namespace), transiently killing every attacker flood whenever a legit
    # host idled or baseline stopped.
    procs = _baseline_slot_procs.pop(host.name, [])
    for proc in procs:
        try:
            proc.kill()
        except Exception:
            pass


def _nsrun(host, cmd: str, wait: bool = False, return_proc: bool = False):
    # run a command inside host netns + pid namespace
    # start_new_session=True detaches child from our process group,
    # so Ctrl+C / SIGINT to this script does not kill the flood too.
    full = f"nsenter -t {host.pid} -n -p -- bash -c {cmd!r}"
    if wait:
        try:
            subprocess.run(full, shell=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            info(f"    nsenter timeout on {host.name}\n")
        return None
    p = subprocess.Popen(
        full, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    return p if return_proc else None


_HOST_START_STATE = {1: "active", 2: "active", 3: "active", 4: "active", 5: "active"}
_STATE_CYCLE = ["active", "idle"]
_idle_slot = threading.Semaphore(1)


def _hping_state(host):
    # True = hping3 running, False = confirmed gone, None = unknown.
    # Only pgrep exit code 1 means no match. Exit codes >= 2 mean pgrep or
    # nsenter itself failed; treating that as death stacked duplicate flood
    # processes on the same host.
    try:
        r = subprocess.run(
            f"nsenter -t {host.pid} -n -p -- pgrep -x hping3",
            shell=True, capture_output=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        info(f"    pgrep timeout on {host.name}, assuming alive\n")
        return None
    if r.returncode == 0:
        return True
    if r.returncode == 1:
        return False
    info(f"    pgrep error on {host.name} (rc={r.returncode}), assuming alive\n")
    return None


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
    proc = None
    if slot_type == "icmp_cont":
        # Single-instance guard (Round 4 F2b): a ping process never exits on
        # its own, so relaunching while one is alive stacks processes and
        # multiplies this host's rate until even MATURE rows cross the
        # anomaly threshold (the h5 repeat-incident mechanism). Scoped to
        # icmp only; tcp/udp slot scripts are short-lived by design.
        if any(q.poll() is None and getattr(q, "slot_icmp", False)
               for q in _baseline_slot_procs.get(host.name, [])):
            return
        prof  = _ICMP_CONTINUOUS[slot_key]
        size  = random.randint(prof[0], prof[1])
        sleep = round(random.uniform(prof[2], prof[3]), 4)
        proc = _nsrun(host, f"ping -i {sleep} -s {size} {SERVER_IP} > /dev/null 2>&1",
                      return_proc=True)
        if proc is not None:
            proc.slot_icmp = True
    elif slot_type == "tcp":
        prof   = _TCP_PROFILES[slot_key]
        size   = random.randint(prof[0], prof[1])
        script = _write_slot_script("tcp", slot_key, size, SERVER_IP)
        proc = _nsrun(host, f"python3 {script} > /dev/null 2>&1", return_proc=True)
    elif slot_type == "udp":
        prof   = _UDP_PROFILES[slot_key]
        size   = random.randint(prof[0], prof[1])
        script = _write_slot_script("udp", slot_key, size, SERVER_IP)
        proc = _nsrun(host, f"python3 {script} > /dev/null 2>&1", return_proc=True)
    # track the live handle so cleanup can kill exact pids; prune finished
    if proc is not None:
        lst = [q for q in _baseline_slot_procs.get(host.name, [])
               if q.poll() is None]
        lst.append(proc)
        _baseline_slot_procs[host.name] = lst

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
        with _baseline_lock:
            _baseline_stop[host.name]    = stop_ev
            _baseline_threads[host.name] = t
        t.start()
        info(f"    {host.name} ({host.IP()}): started\n")


def _stop_baseline_threads() -> None:
    with _baseline_lock:
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
    # Build hping3 command from attacker variant config. --flood keeps the
    # dynamic full-rate behavior; payload sizes are capped so flood
    # bandwidth stays within the VM budget (see _ATTACKER_VARIANTS note).
    variant = _ATTACKER_VARIANTS.get(attacker_num, ("SYN", "-S -p 80", 0, 0))
    atype, flags, _, _ = variant

    if count:
        return f"hping3 {flags} -c {count} {target}"

    return f"hping3 {flags} {target} > /dev/null 2>&1"


def _notify_attack_start(ip: str, attack_type: str) -> None:
    _attack_started_at[ip] = time.time()
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"{BACKEND_API}/api/attack_ground_truth/start",
                data=_json.dumps({"ip": ip, "attack_type": attack_type}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
            return
        except Exception as e:
            if attempt == 2:
                info(f"*** Error: Failed to notify attack start for {ip}: {e}\n")
            time.sleep(1.0)


def _notify_attack_stop(ip: str) -> None:
    _active_attackers.discard(ip)
    # Round 5 S8-lite: carry this campaign's start time as a cutoff so the
    # backend never lets a STRANDED stop post delete a NEWER campaign's GT
    # entry for the same IP (the cross-race V2 identified).
    cutoff = _attack_started_at.pop(ip, 0)
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"{BACKEND_API}/api/attack_ground_truth/stop",
                data=_json.dumps({"ip": ip, "cutoff": cutoff}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
            return
        except Exception as e:
            if attempt == 2:
                info(f"*** Error: Failed to notify attack stop for {ip}: {e}\n")
            time.sleep(1.0)


def _kill_all_attackers(deadline_s: float = 10.0) -> None:
    # SIGKILL every attacker's hping3 CONCURRENTLY: one nsenter/pkill chain
    # per host launched at once, reaped on a shared deadline. Serial sweeps
    # pay one full fork chain per host while many floods pin the CPU, which
    # stretched a stop into minutes; parallel caps wall time at about one
    # chain's duration. Uses -x (exact comm match) so the kill never hits
    # monitor probes, wrapper shells, or unrelated processes.
    procs = []
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_POOL:
            try:
                p = subprocess.Popen(
                    f"nsenter -t {h.pid} -n -p -- pkill -9 -x hping3",
                    shell=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                procs.append(p)
            except Exception as e:
                info(f"    kill spawn failed on {h.name}: {e}\n")
    deadline = time.time() + deadline_s
    for p in procs:
        try:
            p.wait(timeout=max(0.05, deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill()


def _flush_flow_rules(prios, ips=None, proto_wildcard_pri=None,
                      deadline_s: float = 10.0, label: str = "flows") -> None:
    # Round 5 S2/S7: strict per-IP deletes batched into ONE shell-chained
    # call per switch, executed CONCURRENTLY across switches. The old form
    # ran 936 sequential fork chains inside stop_all_attacks (19-37s idle,
    # up to minutes under load). Segments chain with ';' so one failed
    # delete never skips the rest; each segment is an exact-match strict
    # delete (plain `del-flows priority=N` is unreliable on OVS 2.17.9).
    if net is None:
        return
    if ips is None:
        ips = [h.IP() for h in hosts]
    info(f"*** Flushing {label} on {len(net.switches)} switches "
         f"(batched, concurrent)...\n")
    procs = []
    for sw in net.switches:
        segs = [f"ovs-ofctl --strict del-flows {sw.name} "
                f"priority={pri},ip,nw_src={ip}"
                for pri in prios for ip in ips]
        if proto_wildcard_pri is not None:
            # best-effort: resource-guard proto drops carry no nw_src to
            # match on, so delete STRICTLY per L4 protocol (ICMP/TCP/UDP).
            # The plain priority-only del-flows form is REJECTED by the
            # installed OVS 2.17.9, which is exactly how stale priority-50
            # rules survived every earlier stop unnoticed.
            segs += [f"ovs-ofctl --strict del-flows {sw.name} "
                     f"priority={proto_wildcard_pri},ip,nw_proto={pr}"
                     for pr in (1, 6, 17)]
        chain = "; ".join(segs)
        try:
            procs.append(subprocess.Popen(
                f"bash -c {chain!r}", shell=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        except Exception as e:
            info(f"    flush spawn failed on {sw.name}: {e}\n")
    deadline = time.time() + deadline_s
    for p in procs:
        try:
            p.wait(timeout=max(0.05, deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill()


def _notify_gt_stop_all(cutoff: float, retries: int = 3) -> None:
    # Round 5 S6: ONE batched ground-truth stop replaces per-host
    # posts that each retried ~9s against a saturated backend. The cutoff
    # makes it race-safe server-side: GT entries belonging to a campaign
    # started after this stop began are left alone.
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                f"{BACKEND_API}/api/attack_ground_truth/stop_all",
                data=_json.dumps({"cutoff": cutoff}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
            return
        except Exception as e:
            if attempt == retries - 1:
                info(f"*** Warning: batched ground-truth stop failed: {e}\n")
            time.sleep(0.5)


def _discard_attackers_locally() -> None:
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_POOL:
            _active_attackers.discard(h.IP())


def _stop_active_workers() -> None:
    # one attack campaign at a time: any launcher first stops workers from
    # previous campaigns so floods never stack across command types
    _mixed_stop_event.set()
    _stress_stop_event.set()
    deadline = time.time() + 7
    for t in (_campaign_threads + _stress_threads):
        t.join(timeout=max(0.05, deadline - time.time()))
    _campaign_threads.clear()
    _stress_threads.clear()
    if net is not None:
        _kill_all_attackers()



def _attacker_cycle_worker(num: int, stop_event: threading.Event,
                           delay: float = None) -> None:
    # Continuous flood — no rest periods.
    # Staggered start only, then floods until stop_event is set.
    # delay (seconds) overrides the host's own _ATTACKER_START_DELAYS jitter;
    # staged-wave scheduling uses this to time hosts into vector waves.
    h     = net.get(f"h{num}")
    if delay is None:
        delay = _ATTACKER_START_DELAYS.get(num, 0)
    ip    = h.IP()

    # Wait for stagger delay before starting
    # Wait for stagger delay before starting — checks stop_event every
    # 0.1s so short decimal delays (e.g. 0.5s) work and stop is still fast
    waited = 0.0
    while waited < delay:
        if stop_event.is_set():
            return
        time.sleep(0.1)
        waited += 0.1

    atype, _, _, _ = _ATTACKER_VARIANTS.get(num, ("SYN", "", 5000, 0.20))
    cmd = _hping_cmd(num, SERVER_IP)

    _notify_attack_start(ip, atype)
    _active_attackers.add(ip)

    # Restart loop — restarts hping3 if it dies unexpectedly
    while not stop_event.is_set():
        _nsrun(h, cmd)
        # Poll every second, check inside host netns, not system-wide.
        # Restart only on a CONFIRMED death (pgrep exit 1); pgrep or nsenter
        # failures must not trigger spurious restarts that stack floods.
        while not stop_event.is_set():
            time.sleep(1)
            if _hping_state(h) is False:
                break  # confirmed dead, outer loop restarts it

    # Stop flood and notify backend (-x exact match: never kills sibling
    # monitor probes or wrapper shells sharing this pid namespace)
    _nsrun(h, "pkill -9 -x hping3 2>/dev/null; true", wait=True)
    _notify_attack_stop(ip)


def launch_attack(sustained: bool = True) -> None:
    # Launch all attackers using worker threads — threads monitor hping3
    # and keep flood running until stop_all_attacks() is called.
    # sustained flag kept for API compatibility but always runs continuous flood.
    global _mixed_stop_event, _campaign_threads
    _stop_active_workers()
    _mixed_stop_event.clear()
    _campaign_threads.clear()

    info(f"*** Sustained DDoS (thread-managed), all attackers -> {SERVER_IP}\n\n")

    for num in sorted(_ATTACKER_VARIANTS.keys()):
        atype, flags, _, _ = _ATTACKER_VARIANTS[num]
        info(f"    h{num} [{atype}] {flags}\n")

        # Thread watches hping3 — restarts if it dies unexpectedly
        t = threading.Thread(
            target=_attacker_cycle_worker,
            args=(num, _mixed_stop_event),
            name=f"attacker-h{num}",
            daemon=True,
        )
        _campaign_threads.append(t)
        t.start()

        # 100ms stagger — prevents OVS from being hit simultaneously
        time.sleep(0.1)

    info("\n    -> Use  py stop_all_attacks()  to stop.\n")


def launch_syn_flood(attacker_name="h10") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** SYN burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _notify_attack_start(attacker.IP(), "SYN")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_icmp_flood(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** ICMP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _notify_attack_start(attacker.IP(), "ICMP")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_udp_flood(attacker_name="h7") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** UDP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} -> {SERVER_IP}\n")
    _notify_attack_start(attacker.IP(), "UDP")
    _nsrun(attacker, f"{cmd} > /dev/null 2>&1")


def launch_syn_flood_sustained(attacker_name="h10") -> None:
    global _mixed_stop_event, _campaign_threads
    _stop_active_workers()
    _mixed_stop_event.clear()
    num = int(attacker_name[1:])
    info(f"*** SYN sustained: {attacker_name} -> {SERVER_IP}\n")
    t = threading.Thread(
        target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
        name=f"attacker-{attacker_name}", daemon=True,
    )
    _campaign_threads.append(t)
    t.start()


def launch_icmp_flood_sustained(attacker_name="h11") -> None:
    global _mixed_stop_event, _campaign_threads
    _stop_active_workers()
    _mixed_stop_event.clear()
    num = int(attacker_name[1:])
    info(f"*** ICMP sustained: {attacker_name} -> {SERVER_IP}\n")
    t = threading.Thread(
        target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
        name=f"attacker-{attacker_name}", daemon=True,
    )
    _campaign_threads.append(t)
    t.start()


def launch_udp_flood_sustained(attacker_name="h7") -> None:
    global _mixed_stop_event, _campaign_threads
    _stop_active_workers()
    _mixed_stop_event.clear()
    num = int(attacker_name[1:])
    info(f"*** UDP sustained: {attacker_name} -> {SERVER_IP}\n")
    t = threading.Thread(
        target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
        name=f"attacker-{attacker_name}", daemon=True,
    )
    _campaign_threads.append(t)
    t.start()


def _attackers_of_type(atype: str) -> list:
    # Single source of truth for single-vector campaign rosters: every
    # ACTIVE attacker whose fixed variant matches the requested type.
    return sorted(n for n, v in _ATTACKER_VARIANTS.items() if v[0] == atype)


def start_syn_flood_campaign() -> None:
    # SYN flood — every SYN-assigned attacker, continuous, watchdog
    # auto-restarts if killed
    global _mixed_stop_event, _campaign_threads
    nums = _attackers_of_type("SYN")
    _stop_active_workers()
    _mixed_stop_event.clear()
    info("\n" + "=" * 55 + "\n")
    info("  [SYN CAMPAIGN]  " + " ".join(f"h{n}" for n in nums)
         + "  |  Continuous flood\n")
    info("=" * 55 + "\n")
    for num in nums:
        h = net.get(f"h{num}")
        t = threading.Thread(
            target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
            name=f"attacker-h{num}", daemon=True,
        )
        _campaign_threads.append(t)
        t.start()
        info(f"  h{num} ({h.IP()})  {_ATTACKER_VARIANTS[num][1]}\n")
        # 100ms stagger — prevents simultaneous OVS hit and switch disconnects
        time.sleep(0.1)
    info("=" * 55 + "\n")
    info("  Stop: py stop_all_attacks()\n")
    info("=" * 55 + "\n\n")


def start_icmp_flood_campaign() -> None:
    # ICMP flood — every ICMP-assigned attacker, continuous, watchdog
    # auto-restarts if killed
    global _mixed_stop_event, _campaign_threads
    nums = _attackers_of_type("ICMP")
    _stop_active_workers()
    _mixed_stop_event.clear()
    info("\n" + "=" * 55 + "\n")
    info("  [ICMP CAMPAIGN]  " + " ".join(f"h{n}" for n in nums)
         + "  |  Continuous flood\n")
    info("=" * 55 + "\n")
    for num in nums:
        h = net.get(f"h{num}")
        t = threading.Thread(
            target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
            name=f"attacker-h{num}", daemon=True,
        )
        _campaign_threads.append(t)
        t.start()
        info(f"  h{num} ({h.IP()})  {_ATTACKER_VARIANTS[num][1]}\n")
        # 100ms stagger — prevents simultaneous OVS hit and switch disconnects
        time.sleep(0.1)
    info("=" * 55 + "\n")
    info("  Stop: py stop_all_attacks()\n")
    info("=" * 55 + "\n\n")


def start_udp_flood_campaign() -> None:
    # UDP flood — every UDP-assigned attacker, continuous, watchdog
    # auto-restarts if killed
    global _mixed_stop_event, _campaign_threads
    nums = _attackers_of_type("UDP")
    _stop_active_workers()
    _mixed_stop_event.clear()
    info("\n" + "=" * 55 + "\n")
    info("  [UDP CAMPAIGN]  " + " ".join(f"h{n}" for n in nums)
         + "  |  Continuous flood\n")
    info("=" * 55 + "\n")
    for num in nums:
        h = net.get(f"h{num}")
        t = threading.Thread(
            target=_attacker_cycle_worker, args=(num, _mixed_stop_event),
            name=f"attacker-h{num}", daemon=True,
        )
        _campaign_threads.append(t)
        t.start()
        info(f"  h{num} ({h.IP()})  {_ATTACKER_VARIANTS[num][1]}\n")
        # 100ms stagger — prevents simultaneous OVS hit and switch disconnects
        time.sleep(0.1)
    info("=" * 55 + "\n")
    info("  Stop: py stop_all_attacks()\n")
    info("=" * 55 + "\n\n")


def start_mixed_campaign() -> None:
    # all 15 attackers launch in staged VECTOR WAVES (2026-08-27): SYN at
    # t+0, UDP after a randomized 20-30s gap, ICMP after another 20-30s —
    # mimicking how real multi-vector campaigns ramp up and keeping each
    # vector's detection window attributable. Within a wave, hosts keep
    # their own small jitter from _ATTACKER_START_DELAYS on top of the wave
    # base time. Floods are continuous once started, no rest periods.
    global _mixed_stop_event, _campaign_threads
    _stop_active_workers()
    _mixed_stop_event.clear()
    _campaign_threads.clear()

    waves = []            # (attack_type, wave start offset in seconds)
    base = 0.0
    for i, atype in enumerate(("SYN", "UDP", "ICMP")):
        if i:
            base += random.uniform(20.0, 30.0)
        waves.append((atype, base))

    info("\n" + "=" * 65 + "\n")
    info("  [MIXED CAMPAIGN]  All 15 attackers  |  Staged vector waves\n")
    info("=" * 65 + "\n")
    info(f"  {'WAVE':<6} {'HOSTS':<28} FLOOD START\n")
    info("  " + "-" * 66 + "\n")

    schedule = {}         # attacker num -> absolute flood-start delay
    for atype, t_start in waves:
        nums = _attackers_of_type(atype)
        hosts = " ".join(f"h{n}" for n in nums)
        info(f"  {atype:<6} {hosts:<28} t+{t_start:.1f}s\n")
        for n in nums:
            schedule[n] = t_start + _ATTACKER_START_DELAYS.get(n, 0)

    for num in sorted(schedule):
        h = net.get(f"h{num}")
        atype, flags, _, _ = _ATTACKER_VARIANTS[num]
        delay = schedule[num]
        info(f"  h{num:<5} ({h.IP()})  {atype:<8} {flags:<40} +{delay:.1f}s\n")
        thread = threading.Thread(
            target=_attacker_cycle_worker,
            args=(num, _mixed_stop_event),
            kwargs={"delay": delay},
            name=f"attacker-h{num}",
            daemon=True,
        )
        _campaign_threads.append(thread)
        thread.start()

    info("=" * 65 + "\n")
    info("  Stop: py stop_all_attacks()\n")
    info("=" * 65 + "\n\n")



# === STRESS TEST (rand-source) ===

_stress_stop_event = threading.Event()
_stress_threads: list = []


def start_stress_test() -> None:
    # Pure stress test — all attackers use --rand-source to spoof random IPs.
    # Forces controller to track thousands of unknown flows, spiking memory.
    # Use for ML ON or ML OFF controller resource stress measurement.
    # RF accuracy is not meaningful here — random IPs have no flow history.
    global _stress_stop_event, _stress_threads
    # Reuse ONE stop event forever. Rebinding it to a fresh Event stranded
    # old watchdogs on an unset Event object and they kept respawning floods.
    # Stop any running campaign first so floods never stack.
    _stop_active_workers()
    _stress_stop_event.clear()
    _stress_threads.clear()

    info("*** Starting stress test — all 15 attackers, rand-source flood -> {}\n".format(SERVER_IP))

    # Stagger each attacker by 100ms — prevents OVS from being hit by all
    # many floods in the same millisecond, which causes switch disconnects.
    # 100ms per host = ~2.0s total ramp — still appears simultaneous in report.
    def _stress_worker(num: int) -> None:
        h   = net.get(f"h{num}")
        cmd = _STRESS_CMDS[num]
        atype, _, _, _ = _ATTACKER_VARIANTS[num]
        _notify_attack_start(h.IP(), atype)
        # _nsrun uses Popen, survives after this call returns.
        # h.cmd() closes its shell after return, killing any &
        # backgrounded process with it — do not use h.cmd() here.
        _nsrun(h, cmd)
        info(f"    h{num} ({h.IP()}): stress flood started\n")

        # Watchdog: check every 5s if hping3 died on its own.
        # If dead and stop was not requested, relaunch it.
        # Loop only exits when stop_stress_test() sets the stop event.
        while not _stress_stop_event.is_set():
            time.sleep(5)
            if _stress_stop_event.is_set():
                break
            if _hping_state(h) is False:
                info(f"    h{num}: hping3 died, restarting\n")
                _nsrun(h, cmd)

    for i, num in enumerate(sorted(_ATTACKER_NUMS)):
        t = threading.Thread(target=_stress_worker, args=(num,), daemon=True)
        _stress_threads.append(t)
        t.start()
        time.sleep(0.1)

    info("\n    -> Use  py stop_stress_test()  to stop.\n")


def stop_stress_test() -> None:
    # stop all rand-source stress flood processes, inside each host netns
    info("*** Stopping stress test...\n")
    # Round 5 S1: set BOTH stop events before killing. Stress floods die on
    # _stress_stop_event alone, but _kill_all_attackers() kills ALL hping3,
    # including any campaign flood still running; without the campaign event
    # its watchdogs legitimately resurrect those floods.
    _stress_stop_event.set()
    _mixed_stop_event.set()
    gt_cutoff = time.time()
    _kill_all_attackers()
    _discard_attackers_locally()
    _notify_gt_stop_all(gt_cutoff)
    deadline = time.time() + 3
    for t in _stress_threads:
        t.join(timeout=max(0.05, deadline - time.time()))
    _stress_threads.clear()
    info("*** Stress test stopped.\n")


def reset_flow_epochs() -> None:
    # Flush priority-10 forward rules so every host's flow counters restart
    # (bounds the cumulative age drift that slowly pushes clean hosts over
    # the anomaly threshold). Strict per-IP deletes: the plain
    # `del-flows <sw> priority=N` form is rejected by the installed OVS.
    # Requires the controller RUNNING: switches fail secure, so unmatched
    # packets are dropped, not forwarded, while Ryu is down.
    if net is None:
        return
    info("*** Resetting flow epochs (flush priority=10 forwards)...\n")
    ips = [h.IP() for h in hosts]
    for sw in net.switches:
        for ip in ips:
            subprocess.run(
                f"ovs-ofctl --strict del-flows {sw.name} "
                f"priority=10,ip,nw_src={ip}",
                shell=True, capture_output=True)
    info("*** Flow epochs reset.\n")


def stop_all_attacks() -> None:
    global _mixed_stop_event, _campaign_threads

    info("*** Stopping all attacks...\n")

    # Set BOTH stop events FIRST, before killing anything. Stress watchdogs
    # only watch _stress_stop_event, so setting just the campaign event left
    # the entire first kill sweep inside the watchdog restart window, and
    # every sweep iteration resurrected floods.
    _mixed_stop_event.set()
    _stress_stop_event.set()

    # Kill hping3 on all attacker hosts CONCURRENTLY (wall time of one fork chain,
    # not one per host). Workers exit on the already-set events; their own exit
    # pkill is a no-op afterwards.
    gt_cutoff = time.time()
    info("*** Killing hping3 on all attackers (parallel)...\n")
    _kill_all_attackers()
    _discard_attackers_locally()

    # Round 5 S3: starve zombie telemetry immediately after the kill. Dead
    # floods' priority-10 entries keep reporting cumulative-average pps for
    # up to ~60s and the backend re-creates quarantine entries from them.
    # Deleting ONLY attacker forward rules here stops that feed at the
    # source; legit entries keep aging naturally (flushing those would
    # recreate the fresh-entry transients Round 4 fixed).
    _flush_flow_rules([10], ips=[h.IP() for h in net.hosts
                                 if int(h.name[1:]) in _ATTACKER_POOL],
                      label="attacker forwards")

    # Reap stress workers, then campaign workers, on short deadlines.
    # Round 5 S9: stranded workers always terminate and cannot respawn, so
    # long joins only burn wall time against a degraded backend.
    deadline = time.time() + 3
    for t in _stress_threads:
        t.join(timeout=max(0.05, deadline - time.time()))
    _stress_threads.clear()

    info("*** Waiting for attack threads to exit...\n")
    deadline = time.time() + 3
    for t in _campaign_threads:
        t.join(timeout=max(0.05, deadline - time.time()))
    _campaign_threads.clear()

    # One parallel safety pass catches anything spawned during the join
    # window. Cheap when idle; replaces the old second and third serial
    # sweeps that made stops take minutes under flood load.
    _kill_all_attackers()
    # repeat the attacker-scoped forward flush: packets buffered in qdiscs
    # at SIGKILL time can reinstall a priority-10 rule after the first pass
    _flush_flow_rules([10], ips=[h.IP() for h in net.hosts
                                 if int(h.name[1:]) in _ATTACKER_POOL],
                      label="attacker forwards")

    # Round 5 S6: one batched ground-truth stop (race-safe via cutoff)
    _notify_gt_stop_all(gt_cutoff)

    info("*** Flushing OVS block rules...\n")
    # Round 5 S2/S7: batched concurrent flush covering every per-IP
    # mitigation priority (100 ban / 90 time-ban meter / 85 sinkhole
    # redirect / 80 quarantine meter) for ALL known host IPs, plus a
    # best-effort wildcard delete for the resource-guard proto rule at
    # priority 50. reset_flow_epochs() deliberately NOT called here: flow
    # epochs self-heal at FLOW_EPOCH_S and flushing legit forward rules at
    # stop manufactured the fresh-entry transients behind the h1/h2 FPs.
    _flush_flow_rules([100, 90, 85, 80], ips=None,
                      proto_wildcard_pri=50, label="ban rules")

    info("*** Clearing controller state via ZMQ...\n")
    try:
        import zmq as _zmq
        _ctx  = _zmq.Context.instance()
        _sock = _ctx.socket(_zmq.PUSH)
        _sock.setsockopt(_zmq.LINGER, 0)
        _sock.setsockopt(_zmq.SNDTIMEO, 500)
        _sock.connect("tcp://127.0.0.1:5556")
        for h in hosts:
            if int(h.name[1:]) in _ATTACKER_POOL:
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
        if int(h.name[1:]) in _ATTACKER_POOL:
            t = threading.Thread(target=_invalidate, args=(h.IP(),), daemon=True)
            inv_threads.append(t)
            t.start()
    for t in inv_threads:
        t.join(timeout=3)

    # Round 5 S4: bounded verification loop. Worker staleness is up to ~6s
    # (enqueued_at resets on priority requeue) and hold_ip rows live ~15s,
    # so in-flight detections can re-create entries AFTER the first
    # clear_all. Poll, re-clear while dirty, warn only if still dirty.
    verify_deadline = time.time() + 12

    def _clear_quarantine_once() -> None:
        try:
            req2 = urllib.request.Request(
                f"{BACKEND_API}/api/quarantine/clear_all",
                data=b"{}", headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=2) as r:
                resp = _json.loads(r.read())
            info(f"    quarantine cleared: {resp.get('cleared', 0)} entries\n")
        except Exception as e:
            info(f"    backend flush warning: {e}\n")

    _clear_quarantine_once()
    still_dirty = False
    for wait_s in (3.0, 6.0):
        time.sleep(wait_s)
        try:
            with urllib.request.urlopen(f"{BACKEND_API}/api/quarantine_list",
                                        timeout=2) as r:
                leftover = _json.loads(r.read())
        except Exception as e:
            info(f"*** WARNING: could not verify backend state after stop: {e}\n")
            break
        if not leftover:
            break
        if time.time() >= verify_deadline:
            still_dirty = True
            break
        _clear_quarantine_once()
    else:
        still_dirty = bool(leftover)
    if still_dirty:
        info(f"*** WARNING: backend still lists quarantined entries after "
             f"verify loop (possible dirty criminal records; run the wipe "
             f"runbook before the next session)\n")

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
        _kill_baseline_procs(h)
    time.sleep(0.5)

    for h in legit:
        num = int(h.name[1:])
        _flash_crowd_run_slot(h, num)
        info(f"    {h.name} ({h.IP()}): flash crowd -> {SERVER_IP}\n")

    time.sleep(duration)

    for h in legit:
        _kill_baseline_procs(h)

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
    # (legit hosts ONLY, 2026-08-26: retired hosts stay fully silent)
    info("*** Pinging server in parallel to populate MAC tables...\n")
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
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
        if int(h.name[1:]) not in _ATTACKER_POOL:
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
        elif num in _RETIRED_NUMS:
            role, attack_type = "RETIRED", "-"
            status = "standby (silent)"
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
    # restart baseline thread for a legit host released from quarantine.
    # Lock spans check-and-spawn so the restore poller and the baseline
    # watchdog cannot both spawn a replacement for the same host.
    with _baseline_lock:
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
                        f" {str(e.get('confidence','-')):>7} {e.get('action','-')}"                    
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
        elif num in _RETIRED_NUMS:
            role, atype = "RETIRED", "(silent)"
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
    info(f"  py launch_syn_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h10\n")
    info(f"  py launch_icmp_flood()                 # {ATTACK_PKT_COUNT:,} pkts, h11\n")
    info(f"  py launch_udp_flood()                  # {ATTACK_PKT_COUNT:,} pkts, h7\n\n")
    info("  ── SUSTAINED (unlimited) ─────────────────────────────────────\n")
    info("  py launch_syn_flood_sustained()        # h10\n")
    info("  py launch_icmp_flood_sustained()       # h11\n")
    info("  py launch_udp_flood_sustained()        # h7\n\n")
    info("  ── ALL ATTACKERS ─────────────────────────────────────────────\n")
    info("  py launch_attack()                     # all 15, sustained\n")
    info("  py launch_attack(sustained=False)      # all 15, burst\n\n")
    info("  ── CAMPAIGNS ─────────────────────────────────────────────────\n")
    info("  py start_syn_flood_campaign()          # all SYN attackers\n")
    info("  py start_icmp_flood_campaign()         # all ICMP attackers\n")
    info("  py start_udp_flood_campaign()          # all UDP attackers\n")
    info("  py start_mixed_campaign()              # all 15, staged vector waves\n")
    info("  py start_stress_test()                 # all 15, rand-source, memory stress\n\n")
    info("  ── STOP ──────────────────────────────────────────────────────\n")
    info("  py stop_all_attacks()                  # kill + flush + clear\n")
    info("  py stop_baseline()                     # stop baseline\n\n")
    info("  ── OTHER ─────────────────────────────────────────────────────\n")
    info("  py flash_crowd()                       # 30s spike to server\n")
    info("  py flash_crowd(duration=60)            # custom duration\n")
    info("  py check_traffic()                     # live host status\n")
    info("  py reset_flow_epochs()                 # fresh flow counters\n")
    info("  py watch_pipeline()                    # live ML scores\n")
    info("  py start_baseline_traffic()            # restart baseline\n")
    info("=" * 75 + "\n\n")


# === ENTRY POINT ===

if __name__ == "__main__":
    setLogLevel("info")

    net, hosts, edge_switches, distribution = build_star()
    net.start()
    _speed_up_reconnect(edge_switches, net.get("s0"))
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

    # expose host shortcuts as real module globals so py commands always see
    # live state. A copied snapshot goes stale after stop/start cycles.
    for _h in hosts:
        globals()[_h.name] = _h

    class TopologyCLI(CLI):
        def do_py(self, line):
            try:
                result = eval(line, globals())
                if result is not None:
                    print(result)
            except SyntaxError:
                try:
                    exec(line, globals())
                except Exception as e:
                    print(f"Error: {e}")
            except Exception as e:
                print(f"Error: {e}")

    TopologyCLI(net)
    net.stop()