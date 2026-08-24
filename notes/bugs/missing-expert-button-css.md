---
created: 2026-08-20
last-updated: 2026-08-20
status: verified
tags:
  - bugs
  - frontend
  - expert-mode
  - css
---

# Missing CSS: Expert/Light Mode Buttons and Expert Panel Classes

> [!note]
> Fixed on 2026-08-20.

## Description

Two related CSS gaps caused visual issues visible in the dashboard:

### 1. Expert and Light Mode buttons unstyled

`dashboard.html` assigns `class="expert-btn"` and `class="theme-btn"` to the header toggle buttons, but neither class was defined in `style.css`. Both fell through to the base `.btn` rule (gray, no active state). When Expert Mode was activated, `.active` was added to `#expert-btn` but had no style, so it looked identical to the inactive state.

### 2. Expert panel classes entirely missing

`expert.js` injects a large block of HTML into `#expert-ml-content` and `#expert-mitigation-content` using classes that were never added to `style.css`:

- `.expert-hidden` (panels were not hidden by default)
- `.ml-section`, `.ml-section-title`
- `.accent-dot`, `.if-dot`, `.rf-dot`, `.tea-dot`
- `.if-thermometer`, `.if-thermometer-fill`, `.if-thermometer-threshold`, `.if-stats`
- `.rf-segmented-bar`, `.rf-segment` (`.normal`, `.syn`, `.icmp`, `.udp`)
- `.rf-legend`, `.rf-legend-item`, `.rf-legend-dot`
- `.tea-ip-verdicts`, `.tea-ip-list`, `.tea-ip-pill` (verdicts)
- `.terminal-line`, `.t-time`, `.t-ip`
- `.phase-label`, `.phase-count`, `.phase-action`
- `.phase-box` variant borders (`.quarantine`, `.ban`, `.blackhole`, `.probation`)
- `.panel-icon`

## Fix

Added all missing classes to `style.css` (appended after the Export section, above the trailing blank line). Also added light-mode overrides for the new expert panel classes and header buttons. Bumped `style.css` cache-bust version from `v=4` to `v=5` in `dashboard.html`.

## Related Notes

- [[bugs/infinite-scroll-chartjs]]: related ChartJS layout fix
- [[frontend/design-system]]: design system and CSS conventions
- [[tasks/expert-mode-tea-visualization-plan]]: expert mode plan that introduced these classes
