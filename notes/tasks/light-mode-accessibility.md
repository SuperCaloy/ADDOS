---
created: 2026-08-21
last-updated: 2026-08-21
status: done
area: [frontend, ui-ux, accessibility]
---

# Task: Light Mode Accessibility Refactor

Fix WCAG AA contrast failures in light mode and make canvas pipeline legible on light backgrounds.

## Spec

`docs/superpowers/specs/2026-08-21-light-mode-accessibility-design.md`

## Checklist

- [x] Update light mode CSS variables (`--bg`, `--surface`, `--card`, `--border`, `--border2`, `--sub`, `--sub2`, `--terminal-bg`)
- [x] Add light mode overrides for pipeline elements (canvas wrap, formula block, I/O cols, stats, proto items, terminal)
- [x] Add `isLightMode` flag in `ExpertPipeline.init()`
- [x] Use conditional colors in `drawScene()` for paths, strokes, labels, feedback elements
- [x] Run Playwright tests (6/6 passing)
- [x] Create spec doc
- [x] Create note
- [x] Update `notes/index.md`
- [x] Update `notes/frontend/expert-pipeline-visualization.md`
- [x] Update `notes/ui-ux/redesign-plan.md` Phase 3 items

## Verification

- [x] Playwright E2E tests pass (6/6)
- [x] Manual visual check: light mode shows clear card boundaries, legible text, visible canvas elements
- [x] Dark mode untouched

## Related

- [[frontend/light-mode-accessibility]]
