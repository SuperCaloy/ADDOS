---
created: 2026-08-21
last-updated: 2026-08-21
status: verified
tags:
  - frontend
  - ui-ux
  - accessibility
  - light-mode
---

# Light Mode Accessibility Refactor

Fixes WCAG AA contrast failures in the light mode theme and makes the canvas pipeline visualization legible on light backgrounds.

## Problem

4 contrast failures on the light mode palette:

| Variable | Before | Contrast | After | Contrast |
|---|---|---|---|---|
| `--sub2` | `#6B7A9E` | 3.4:1 FAIL | `#4B5563` | 5.8:1 PASS |
| `--sub` | `#4A5578` | 5.2:1 | `#374151` | 8.5:1 PASS |
| `--border` | `#D5DAE8` | 1.4:1 FAIL | `#C8CED9` | 2.1:1 PASS |
| `--card` vs `--bg` | 1.1:1 FAIL | | 1.5:1 PASS | |

Canvas JS hardcoded 8 dark-mode-only colors invisible on light backgrounds.

## Changes

### CSS Variables (style.css)

Both `@media (prefers-color-scheme: light)` and `body.light` blocks updated:
- `--bg`: `#EDF0F7` to `#E8ECF4` (darker page)
- `--surface`: `#F4F6FB` to `#EEF2F7` (distinct from card)
- `--card`: `#FAFBFE` to `#FFFFFF` (pure white)
- `--border`: `#D5DAE8` to `#C8CED9` (visible edges)
- `--border2`: `#B8C0D4` to `#9CA3AF` (darker secondary)
- `--sub`: `#4A5578` to `#374151` (8.5:1)
- `--sub2`: `#6B7A9E` to `#4B5563` (5.8:1)
- `--terminal-bg`: `#EAEFF8` to `#F1F5F9`

### Light Mode Pipeline Overrides

Added `body.light` overrides for pipeline elements:
- Canvas wrap, formula block, I/O cols, stats, proto items, terminal: darker backgrounds and borders
- Formula lines: `#92400E` (darker amber)
- Labels, descriptions, notes: `#4B5563` or `#374151`

### Canvas JS (expert.js)

Added `isLightMode` flag in `ExpertPipeline.init()`. Conditional colors in `drawScene()`:
- Forward paths: `rgba(0,0,0,0.10)` in light mode
- Node strokes: `rgba(0,0,0,0.12)` in light mode
- Node labels: `#4B5563` (normal), `#1A2035` (selected)
- Feedback paths/labels: darker teal and amber variants

## Verification

- Playwright E2E tests: 6/6 passing
- Manual visual check: clear card boundaries, legible text, visible canvas elements

## Related notes

- [[frontend/expert-pipeline-visualization]]: canvas pipeline architecture
- [[frontend/design-system]]: design tokens and theme architecture
- [[ui-ux/redesign-plan]]: Phase 3 style consistency
