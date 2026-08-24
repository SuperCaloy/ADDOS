---
created: 2026-08-21
last-updated: 2026-08-21
status: done
area: [backend, controller, frontend]
---

# Bug Fixes Batch (2026-08-21)

Comprehensive fix for all open bugs and known issues.

## Completed

- [x] **Fix 1a:** Ryu controller throttle starvation. Non-banned IPs under throttle now get forward rules installed instead of being flooded. Breaks the feedback loop that makes IPs invisible to ML. (`controller/ryu_controller.py`)
- [x] **Fix 1b:** State machine probation re-offence threshold. `update_observation` now accepts Phase 2/3/4 IPs. `tick` for Phase 4 checks if IP is still flooding before clearing. (`backend/mitigation/state_machine.py`)
- [x] **Fix 1c:** ZMQ receiver scores Phase 2/3 IPs. TEA is skipped but flow_stats still submitted to worker for IF/RF scoring. Eliminates frozen if_score artifact. (`backend/transport/zmq_receiver.py`)
- [x] **Issue #2:** Sinkhole redirect handler. Added `redirect` branch in `_apply_command` with `_install_redirect_rule` helper (priority 85, SET_FIELD ipv4_dst, OUTPUT NORMAL). (`controller/ryu_controller.py`)
- [x] **Issue #4:** Frontend comment fixes. Updated stale "every 5s" comments to match actual intervals. (`frontend/static/main.js`, `frontend/templates/dashboard.html`)
- [x] **Issue #5:** .gitignore entries. Added `node_modules/` and `package-lock.json`. (`.gitignore`)

## Not fixed (by design)

- [ ] **Issue #3:** Hardcoded topology knowledge. Intentional for ML model accuracy. Not a bug.
- [ ] **Issue #6:** Unused dependencies in requirements.txt. Removed from plan per user request.

## Verification needed

- 20-attacker simulation run to confirm `active_threats` stays at ~20 throughout
- Confirm "Probation Complete" releases drop to near zero during active attack
- Confirm sinkhole redirect works (traffic reaches 10.0.0.21)

## Related notes

- [[bugs/attack-detection-dropoff]]: root cause analysis and resolution details.
- [[known-issues/known-issues]]: updated with resolution notes.
