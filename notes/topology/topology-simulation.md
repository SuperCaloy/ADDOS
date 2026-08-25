---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - topology
  - simulation
  - mininet
---

# Topology & Simulation

**File:** `topology/topology.py` (1362 lines)

The Mininet network emulator + traffic/simulation driver.

## Topology Construction

- **No LLDP discovery**: network layout is statically defined:
  - 1 core switch `s0` (dpid `0000000000000001`), 8 edge switches `s1`-`s8` (dpids `2`-`9`).
  - Flat star topology (core + 8 edges).
  - Fixed `_HOST_TO_SWITCH` mapping: h1-h19 + h22-h27 spread across s1-s7; **h20 server alone on s8**; **h21 sinkhole directly on core**.
  - Flat `10.0.0.x/24` addressing, `autoSetMacs=True`, `autoStaticArp=True`.
  - Remote controller `c0` at `127.0.0.1:6633`.
- `_speed_up_reconnect` sets OVS `inactivity_probe=1000 max_backoff=1000` via `ovs-vsctl` so controller failures are detected fast.

## Traffic Roles

- **Legit hosts (`_LEGIT_NUMS = {1..5}`):** h1, h2 (TCP-heavy); h3, h4 (UDP); h5 (ICMP). Daemon threads (`_baseline_loop`) send continuous realistic background traffic. `_idle_rotator` forces one host idle every 60s.
- **Attackers (`_ATTACKER_NUMS = {6..19, 22..27}`, 20 total):** hping3-based campaigns:
  - Variants: 10 SYN, 7 ICMP, 2 UDP, 1 MIXED (h19 fires SYN+UDP simultaneously; a combo not in training data).
- **Server:** h20 (`10.0.0.20`), runs raw L4 TCP/UDP listeners.
- **Sinkhole:** h21 (`10.0.0.21`), silent dummy host.

## Key Capabilities

- **Baseline traffic & watchdog:** restarts dead baseline threads every 30s.
- **Attack campaigns:** `launch_attack()`, `launch_syn_flood`, `launch_icmp_flood`, `launch_udp_flood`, sustained campaigns, **stress test** (`--rand-source` spoofed IPs to test controller memory).
- **Flash crowd:** `flash_crowd()`: all legit hosts spike simultaneously.
- **Warmup:** resets Ryu state (`{"action":"reset"`), populates MAC tables via parallel pings, clears backend flood-prefilter flags for legit hosts, sends `{"action":"warmup_done"}`.
- **Interactive CLI:** `TopologyCLI` subclass allows running Python snippets (`net`, `hosts`, `h1`...) directly inside Mininet CLI.
- **Auto-restore:** polls backend `/api/pending_restores` every 5s and restores baseline traffic for released IPs.

## Backend Integration

- **→ Ryu (ZMQ port 5556):** `reset`, `clear`, `warmup_done`.
- **→ Backend API (HTTP):** `POST /api/attack_ground_truth/start|stop`, `/api/cache/invalidate`, `/api/quarantine/clear_all`.
- **← Backend API (HTTP):** polls `/api/quarantine_list`, `/api/stats`, `/api/pending_restores`.

## Related notes

- [[controller/ryu-controller]]: the controller being driven.
- [[overview/architecture]]: how telemetry flows back to the backend.