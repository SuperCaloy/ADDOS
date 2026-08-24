---
created: 2026-08-23
last-updated: 2026-08-23
status: done
area: [backend, pipeline, expert-mode]
---

# Task: Fix Expert Mode Flow Reading Bug

## Context

User reports "backend doesn't read flows" after expert-mode-tea-visualization update. Root cause analysis identified 4 bugs causing the expert panel to show no data.

See [[bugs/expert-mode-flow-reading-bug]] for full analysis.

## Steps

- [x] Fix Bug #2: Add lock acquisition in `expert.py:66` and `expert.py:151`
- [x] Fix Bug #4: Add top-level exception handler in `zmq_receiver.py:_parse_and_route`
- [x] Fix Bug #1: Clear `_flow_buffer` after TEA evaluation in `entropy_analyzer.py`
- [x] Fix Bug #3: Correct attribute references in `ip_detail.py:232-237,120`
- [x] Fix flow snapshot: `_switch_flows[dpid]` cleared after each snapshot to prevent duplicate flows
- [x] Fix flow buffer: `_flow_buffer` accumulates between evaluations, cleared only on actual eval (not early return)
- [x] **Fix deadlock: Change `entropy_analyzer._lock` from `Lock()` to `RLock()` to prevent nested lock deadlock**
- [ ] Remove dead code: `switch_delta_pps` at `zmq_receiver.py:200`
- [x] Verify `/api/expert/live` returns 200 with data
- [x] Verify expert panel shows live flow data
- [x] Verify no `RuntimeError` in logs
- [x] Update notes with fix details

## Verification

- Run backend, trigger traffic, check expert panel shows data
- Check logs for no thread crashes or dictionary errors
- Verify TEA entropy values change with traffic patterns

## Notes

- Bug #2 is the most likely cause of the visible symptom
- All fixes are surgical, touching only the broken code paths
- No changes to pipeline logic, only thread safety and exception handling
