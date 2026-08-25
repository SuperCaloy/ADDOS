---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
---

# Reputation Scoring Fix

## Problem

Repeat offender reputation scores stayed flat because offenses were only recorded when an IP was cleared, and `should_blackhole()` compared the raw offense count against a threshold meant for a half-life decay score.

## Changes

- `backend/mitigation/behavioral.py`
  - `should_blackhole()` now calls `get_decay_score(src_ip)` instead of `get_offences(src_ip)`.
  - Log line updated to print `decay_score`.

- `backend/mitigation/state_machine.py`
  - `_advance_to_ban()` records an offense to `ip_attack_history` after logging the mitigation event.
  - `_advance_to_blackhole()` records an offense to `ip_attack_history` after logging the mitigation event.
  - `manual_release()` now passes `ban_level` and `offence_count` to `writer.log_attack_history()` so the manual release entry preserves the IP's final state.

## Verification

- Smoke check: `python3 -c "from backend.mitigation.state_machine import state_machine; print('ok')"` passed.
- Scratch test: `PYTHONPATH=/home/killua/Documents/ADDOS-NEW python3 scratch/verify_reputation_fix.py` printed `Reputation scoring fix VERIFIED`.

## Note

The verbatim scratch script as written requires `PYTHONPATH` set to the repo root when invoked as `python3 scratch/verify_reputation_fix.py`, because Python adds the script directory to `sys.path`, not the current working directory.

## See Also

- [[tasks/regression-fix-plan-2026-08-24]]: P0 extends this fix with the offence_count column in the DB schema and writer
