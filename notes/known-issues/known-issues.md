---
created: 2026-08-19
last-updated: 2026-08-21
status: verified
tags:
  - known-issues
  - bugs
  - gaps
---

# Known Issues & Gaps

Gaps, dead code, and discrepancies discovered during codebase exploration.

## 1. Sinkhole Redirect is Not Implemented in the Ryu Controller

> [!note] Fixed
> Resolved on 2026-08-21. See resolution below.

- **Severity:** Medium (Deception feature incomplete)
- **Description:** `backend/mitigation/deception.py` invokes `_push_redirect` which sends `{"action": "redirect", "src_ip": ..., "redirect_to": "10.0.0.21"}` over ZMQ. `backend/mitigation/traffic_filter.py` defines `ACTION_REDIRECT`. However, `controller/ryu_controller.py` (`_apply_command`) has **no `redirect` branch**: the command is received by the controller but silently ignored.
- **Impact:** Phase 1 unresolved vector escalation to sinkhole works in backend state, but traffic is not actually redirected to the sinkhole (`10.0.0.21`) at the OpenFlow data plane.
- **Resolution (2026-08-21):** Added `redirect` branch in `_apply_command` with `_install_redirect_rule` helper. Installs OpenFlow flow at priority 85: match `ipv4_src`, SET_FIELD `ipv4_dst` to sinkhole, OUTPUT via NORMAL. Also added "redirect" to `_banned_ips` tracking and `_resolve_target_switches`. `_install_clear_rules` and `_install_drop_rule` now clean up stale p85 redirect rules.

## 2. Hardcoded Topology Knowledge Duplicated Across Modules

> [!note] By design
> This is intentional to preserve ML model accuracy. Not a bug.

- **Severity:** Low (Maintainability)
- **Description:** Attacker IP ranges (`10.0.0.6-19, 22-27`), legit host ranges (`10.0.0.1-5`), and whitelisted IPs (`10.0.0.20` server, `10.0.0.21` sinkhole) are hardcoded independently across multiple files (`worker.py`, `decision_engine.py`, `zmq_receiver.py`, `deception.py`, `ryu_controller.py`, `topology.py`).
- **Impact:** Adding/moving a host in topology requires updating constants across multiple backend and controller files.
- **Status:** Intentional. The hardcoded IP ranges are required for ML model accuracy. Not to be refactored.

## 3. Frontend Comment & Polling Discrepancies

> [!note] Fixed
> Resolved on 2026-08-21.

- **Severity:** Trivial (Documentation mismatch)
- **Description:**
  - `frontend/static/main.js` comment states stats poll happens "every 5s", but the actual interval constant `POLL_MS` is `2000` (2s).
  - `frontend/templates/dashboard.html` comment claims system metrics and model info poll every 5s/30s, but the inline script actually executes `setInterval(..., 1000)` (1s).
- **Resolution (2026-08-21):** Fixed comments to match actual intervals: "every 2s" in main.js, "every 1s" in dashboard.html.

## 4. Vestigial package-lock.json

> [!note] Fixed
> Resolved on 2026-08-21.

- **Severity:** Trivial
- **Description:** `/home/killua/Documents/ADDOS-NEW/package-lock.json` exists as an 88-byte stub, but there is no `package.json` in the repository (this is a Python + FastAPI/Flask project, not Node.js).
- **Resolution (2026-08-21):** Added `node_modules/` and `package-lock.json` to `.gitignore`.

## 5. Unused Dependencies in requirements.txt

- **Severity:** Trivial
- **Description:** `scipy`, `imbalanced-learn`, `matplotlib`, `seaborn`, and `python-iptables` are listed in `requirements.txt` but are never imported or used by runtime code. They pertain solely to offline model training and firewall experiments.

## 6. Restart Drops Probation and Sinkhole Entries (deferred)

> [!warning] Deferred from [[tasks/mitigation-event-logging]]
> Deliberately out of scope for the event-ledger work (user decision, 2026-08-21).

- **Severity:** Medium (post-restart only)
- **Description:** Entering probation deletes the IP's `quarantine_state` row while the IP is still actively managed; sinkhole entries live only in `DeceptionModule._entries` (memory). On backend restart, `restore_from_db()` cannot reinstate either: watched IPs are silently dropped.
- **Impact:** After a crash mid-probation or mid-sinkhole, those IPs return to unrestricted traffic until re-detected. Event ledger is unaffected (transitions/released rows already written).

## 7. Archive Table Lacks Latency Columns

- **Severity:** Trivial (impact nil)
- **Description:** `mitigation_events_archive` has no `detection_ms`/`mitigation_ms`; archiver drops them by explicit column list. `get_latency_metrics()` only queries the hot table, so averages are unaffected; rotated rows simply lose latency detail.

## Related notes

- [[backend/mitigation]]: deception module.
- [[controller/ryu-controller]]: command listener.
- [[topology/topology-simulation]]: host IP definitions.