import time
import random
import subprocess
import threading
import urllib.request
import json as _json
import logging as _logging

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
ATTACK_PKT_COUNT = 5000
WHITELIST_IPS    = {SERVER_IP}   # never ML-scored

# odd = attacker, even = legit, h20 = server
_ATTACKER_NUMS = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
_LEGIT_NUMS    = {2, 4, 6, 8, 10, 12, 14, 16, 18}

# Each attacker has a fixed distinct hping3 signature
_ATTACKER_VARIANTS = {
    1:  ("SYN",  "-S -p 80 --flood"),
    3:  ("SYN",  "-S -p 443 --flood"),
    5:  ("SYN",  "-S -p 8080 --flood"),
    7:  ("ICMP", "--icmp --flood"),
    9:  ("ICMP", "--icmp --flood --data 120"),
    11: ("UDP",  "--udp -p 53 --flood"),
    13: ("UDP",  "--udp -p 80 --flood"),
    15: ("UDP",  "--udp -p 443 --flood"),
    17: ("SYN",  "-S -p 8443 --flood"),
    19: ("ICMP", "--icmp --flood --data 64"),
}

# Per-host traffic profiles: state → (interval_range, duration_range)
_HOST_BASELINE_PROFILES = {
    2:  {"idle": ((0.3,  0.8),   (8,  20)), "browsing": ((0.01, 0.03),  (5,  12)), "watching": ((0.005,0.01),  (20, 80)),  "downloading": ((0.001,0.003), (8,  20))},
    4:  {"idle": ((0.4,  1.0),   (8,  20)), "browsing": ((0.02, 0.05),  (5,  12)), "watching": ((0.008,0.015), (20, 80)),  "downloading": ((0.002,0.004), (8,  20))},
    6:  {"idle": ((0.5,  1.2),   (10, 25)), "browsing": ((0.03, 0.07),  (5,  15)), "watching": ((0.01, 0.02),  (25, 90)),  "downloading": ((0.003,0.006), (8,  25))},
    8:  {"idle": ((0.5,  1.5),   (10, 30)), "browsing": ((0.04, 0.09),  (5,  15)), "watching": ((0.01, 0.02),  (30, 100)), "downloading": ((0.003,0.007), (10, 30))},
    10: {"idle": ((0.6,  1.8),   (10, 30)), "browsing": ((0.05, 0.12),  (5,  15)), "watching": ((0.012,0.025), (30, 110)), "downloading": ((0.004,0.008), (10, 30))},
    12: {"idle": ((0.8,  2.0),   (12, 35)), "browsing": ((0.07, 0.15),  (5,  15)), "watching": ((0.015,0.03),  (30, 120)), "downloading": ((0.005,0.01),  (10, 30))},
    14: {"idle": ((1.0,  2.5),   (15, 40)), "browsing": ((0.1,  0.2),   (5,  15)), "watching": ((0.02, 0.04),  (30, 120)), "downloading": ((0.007,0.012), (10, 30))},
    16: {"idle": ((1.5,  3.0),   (15, 45)), "browsing": ((0.15, 0.3),   (5,  15)), "watching": ((0.03, 0.06),  (30, 120)), "downloading": ((0.01, 0.02),  (10, 30))},
    18: {"idle": ((2.0,  5.0),   (20, 60)), "browsing": ((0.2,  0.5),   (5,  15)), "watching": ((0.05, 0.1),   (30, 120)), "downloading": ((0.015,0.03),  (10, 30))},
}

_DEFAULT_DURATIONS = {
    "idle": (10, 30), "browsing": (5, 15), "watching": (30, 120), "downloading": (10, 30),
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


def _baseline_loop(host, stop_event: threading.Event) -> None:
    # Cycles states independently, always pings server (whitelisted — no FP risk)
    num      = int(host.name[1:])
    profile  = _HOST_BASELINE_PROFILES.get(num)
    states   = ["idle", "browsing", "watching", "downloading"]

    first_cycle = True
    while not stop_event.is_set():
        state_name = "idle" if first_cycle else random.choice(states)
        first_cycle = False
        if profile and state_name in profile:
            interval_range, duration_range = profile[state_name]
        else:
            interval_range = (0.5, 2.0)
            duration_range = _DEFAULT_DURATIONS.get(state_name, (10, 30))

        interval = round(random.uniform(*interval_range), 4)
        duration = random.randint(*duration_range)
        _nsrun(host, "pkill -f 'ping -i' 2>/dev/null; true", wait=True)
        _nsrun(host, f"ping -i {interval} {SERVER_IP} > /dev/null 2>&1")

        for _ in range(duration):
            if stop_event.is_set():
                break
            time.sleep(1)

    _nsrun(host, "pkill -f 'ping -i' 2>/dev/null; true", wait=True)


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
    _, flags   = _ATTACKER_VARIANTS.get(attacker_num, ("SYN", "-S -p 80 --flood"))
    count_flag = f"-c {count} " if count else ""
    return f"hping3 {flags} {count_flag}{target}"


def launch_attack(sustained: bool = True) -> None:
    # Launch all 10 attackers simultaneously
    count = None if sustained else ATTACK_PKT_COUNT
    info(f"*** {'Sustained' if sustained else 'Burst'} DDoS — all attackers → {SERVER_IP}\n\n")
    for a in _attack_assignments:
        num      = int(a["attacker"][1:])
        attacker = net.get(a["attacker"])
        cmd      = _hping_cmd(num, SERVER_IP, count)
        info(f"    {a['attacker']} ({attacker.IP()})  [{a['attack_type']}] {a['flags']}\n")
        attacker.cmd(f"{cmd} > /dev/null 2>&1 &")
    info("\n    → Use  py stop_all_attacks()  to stop.\n")


def launch_syn_flood(attacker_name="h1") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** SYN burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{cmd} > /dev/null 2>&1 &")


def launch_icmp_flood(attacker_name="h7") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** ICMP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{cmd} > /dev/null 2>&1 &")


def launch_udp_flood(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    cmd = _hping_cmd(int(attacker_name[1:]), SERVER_IP, ATTACK_PKT_COUNT)
    info(f"*** UDP burst ({ATTACK_PKT_COUNT:,} pkts): {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{cmd} > /dev/null 2>&1 &")


def launch_syn_flood_sustained(attacker_name="h1") -> None:
    attacker = net.get(attacker_name)
    info(f"*** SYN sustained: {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1 &")


def launch_icmp_flood_sustained(attacker_name="h7") -> None:
    attacker = net.get(attacker_name)
    info(f"*** ICMP sustained: {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1 &")


def launch_udp_flood_sustained(attacker_name="h11") -> None:
    attacker = net.get(attacker_name)
    info(f"*** UDP sustained: {attacker_name} → {SERVER_IP}\n")
    attacker.cmd(f"{_hping_cmd(int(attacker_name[1:]), SERVER_IP)} > /dev/null 2>&1 &")


def start_syn_flood_campaign() -> None:
    # h1 (p80), h3 (p443), h5 (p8080), h17 (p8443)
    info("*** [CAMPAIGN] SYN — 4 attackers\n")
    for num in [1, 3, 5, 17]:
        h = net.get(f"h{num}")
        h.cmd(f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1 &")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    → Use  py stop_all_attacks()  to stop.\n")


def start_icmp_flood_campaign() -> None:
    # h7 (plain), h9 (data 120), h19 (data 64)
    info("*** [CAMPAIGN] ICMP — 3 attackers\n")
    for num in [7, 9, 19]:
        h = net.get(f"h{num}")
        h.cmd(f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1 &")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    → Use  py stop_all_attacks()  to stop.\n")


def start_udp_flood_campaign() -> None:
    # h11 (p53), h13 (p80), h15 (p443)
    info("*** [CAMPAIGN] UDP — 3 attackers\n")
    for num in [11, 13, 15]:
        h = net.get(f"h{num}")
        h.cmd(f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1 &")
        info(f"    h{num} ({h.IP()}) [{_ATTACKER_VARIANTS[num][1]}]\n")
    info("    → Use  py stop_all_attacks()  to stop.\n")


def start_mixed_campaign() -> None:
    # All 10 attackers with distinct SYN/ICMP/UDP variants
    info("*** [CAMPAIGN] Mixed — all 10 attackers\n")
    for num, (atype, flags) in _ATTACKER_VARIANTS.items():
        h = net.get(f"h{num}")
        h.cmd(f"{_hping_cmd(num, SERVER_IP)} > /dev/null 2>&1 &")
        info(f"    h{num} ({h.IP()}) [{atype}] {flags}\n")
    info("    → Use  py stop_all_attacks()  to stop.\n")


def stop_all_attacks() -> None:
    # Kill hping3, flush OVS rules, clear controller + backend state
    info("*** Stopping all attacks...\n")
    for h in net.hosts:
        if int(h.name[1:]) in _ATTACKER_NUMS:
            h.cmd("pkill -f hping3 2>/dev/null; true")

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

    info("*** Flushing backend state...\n")
    try:
        for h in hosts:
            if int(h.name[1:]) in _ATTACKER_NUMS:
                try:
                    req = urllib.request.Request(
                        f"{BACKEND_API}/api/cache/invalidate",
                        data=_json.dumps({"src_ip": h.IP()}).encode(),
                        headers={"Content-Type": "application/json"}, method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=2):
                        pass
                except Exception:
                    pass
        req2 = urllib.request.Request(
            f"{BACKEND_API}/api/quarantine/clear_all",
            data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req2, timeout=2) as r:
            resp = _json.loads(r.read())
        info(f"    quarantine cleared: {resp.get('cleared', 0)} entries\n")
    except Exception as e:
        info(f"    backend flush warning: {e}\n")

    time.sleep(1)
    info("*** Attack stopped — forwarding restored.\n")


# === FLASH CROWD ===

_FLASH_CROWD_PROFILES = {
    2: ("0.001","~1000 pps"), 4: ("0.002","~500 pps"),  6: ("0.005","~200 pps"),
    8: ("0.01", "~100 pps"), 10: ("0.02", "~50 pps"),  12: ("0.05", "~20 pps"),
    14: ("0.07","~14 pps"),  16: ("0.1",  "~10 pps"),  18: ("0.15", "~7 pps"),
}


def flash_crowd(duration: int = 30) -> None:
    # All legit hosts spike to server — simulates viral/ticket-sale event (server is whitelisted, tests IF boundary)
    legit = [h for h in hosts if int(h.name[1:]) in _LEGIT_NUMS]
    info(f"*** Flash crowd — {len(legit)} legit hosts → SERVER ({SERVER_IP}) for {duration}s\n\n")
    for ev in _baseline_stop.values():
        ev.set()
    for h in legit:
        num = int(h.name[1:])
        interval, label = _FLASH_CROWD_PROFILES.get(num, ("0.05", "~20 pps"))
        h.cmd("pkill -f 'ping -i' 2>/dev/null; true")
        h.cmd(f"ping -i {interval} {SERVER_IP} > /dev/null 2>&1 &")
        info(f"    {h.name} ({h.IP()}): {label} → {SERVER_IP}\n")
    info(f"\n    Running for {duration}s...\n")
    time.sleep(duration)
    info("*** Flash crowd ended — restoring baseline...\n")
    start_baseline_traffic()


# === WARMUP ===

def _warmup_macs() -> None:
    # Install FLOOD rules so warmup pings bypass Ryu entirely (no packet-in surge on startup)
    info("*** Warmup — installing FLOOD rules (Ryu bypassed)...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl add-flow {sw.name} priority=0,actions=FLOOD",
                       shell=True, capture_output=True)

    info("*** Pinging legit pairs to populate MAC tables...\n")
    legit = [h for h in hosts if int(h.name[1:]) not in _ATTACKER_NUMS]
    for src in legit:
        for dst in legit:
            if src is dst:
                continue
            src.cmd(f"ping -c1 -W1 {dst.IP()} > /dev/null 2>&1")

    # Remove FLOOD rules — Ryu takes back full control
    info("*** Removing FLOOD rules — Ryu resuming control...\n")
    for sw in net.switches:
        subprocess.run(f"ovs-ofctl del-flows {sw.name} priority=0",
                       shell=True, capture_output=True)

    info("*** Waiting 10s for flows to age...\n")
    time.sleep(10)
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
    param = "anomaly_only=1&" if anomaly_only else ""
    url   = f"{BACKEND_API}/api/debug?{param}n={n}"
    info("*** Pipeline viewer — Ctrl+C to stop\n\n")
    try:
        while True:
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    entries = _json.loads(r.read()).get("entries", [])
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
    info("  A-DDoS Star Topology  |  1 core + 8 edge switches  |  20 hosts\n")
    info(f"  Server: h20 ({SERVER_IP}) — whitelisted, never ML-scored\n")
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