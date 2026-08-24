---
created: 2026-08-19
last-updated: 2026-08-19
status: verified
tags:
  - bugs
  - backend
  - expert-api
---
	
# Expert API AttributeError

> [!note]
> This crash was fixed on 2026-08-19.

## Description

The backend crashed when calling `/api/expert/live` with the following error:

```python
AttributeError: '_SwitchEntropyState' object has no attribute 'current'
```

This occurred in `backend/api/expert.py` when attempting to read `curr = state.current` from an instance of `_SwitchEntropyState` defined in `backend/pipeline/entropy_analyzer.py`. The `_SwitchEntropyState` class never had a `current` attribute.

Furthermore, even if the API retrieved `state.latest()` (the most recent window snapshot), the raw snapshot only contained raw entropies (`diversity_entropy`, `packetrate_entropy`, `unique_ips`), meaning the API's fields for computed anomalies (like `diversity_zscore` or `is_attack_pattern`) would default to `0` or `False`.

## Fix

We introduced a `last_result` property on `_SwitchEntropyState` that stores the fully computed outcome dictionary produced by `EntropyAnalyzer.update()`.

1. **`entropy_analyzer.py`**: Added `self.last_result = {}` in `_SwitchEntropyState.__init__`, and saved `result` to `state.last_result` at the end of the `update()` method (including the early neutral return path).
2. **`expert.py`**: Updated the reference to `curr = getattr(state, 'last_result', {})`, which provides the correct dictionary with all pre-computed anomaly z-scores, baselines, and booleans needed for the frontend visualization without needing to recompute them or face missing attributes.

## Related Notes

- [[bugs/expert-mode-flow-reading-bug]]: subsequent expert mode flow reading issue
- [[tasks/expert-mode-tea-visualization-plan]]: original TEA visualization plan
- [[frontend/expert-pipeline-visualization]]: expert pipeline UI design
