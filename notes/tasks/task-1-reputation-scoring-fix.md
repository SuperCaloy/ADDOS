---
created: 2026-08-23
last-updated: 2026-08-23
status: done
area: [mitigation, backend]
---

# Task 1: Reputation Scoring Fix

- [x] Fix `should_blackhole()` to use decay score
- [x] Record offense on ban escalation
- [x] Record offense on blackhole escalation
- [x] Fix `manual_release()` to preserve `ban_level`
- [x] Smoke check
- [x] Write verification script
- [x] Run verification

Result: [[mitigation/reputation-scoring-fix|Reputation scoring fix]]

## See Also

- [[tasks/regression-fix-plan-2026-08-24]]: P0 extends this fix with the offence_count column addition
