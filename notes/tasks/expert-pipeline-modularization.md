---
created: 2026-08-21
last-updated: 2026-08-21
status: done
area: [frontend, ui-ux]
---

# Task: Expert Pipeline Visualization Modularization

Extract `visualization.html` into modular `expert.js`, integrate into dashboard, connect to live backend.

## Spec

`docs/superpowers/specs/2026-08-21-expert-pipeline-visualization-design.md`

## Checklist

- [x] Add `ExpertState`, `ExpertStages`, `ExpertPipeline`, `ExpertMetrics` namespaces to `expert.js`
- [x] Migrate 264 lines of inline CSS from `visualization.html` to `style.css` under `.expert-pipeline-*`
- [x] Add pipeline panel HTML to `dashboard.html` Expert Mode section
- [x] Wire `ExpertPipeline.init()` to canvas container, handle resize
- [x] Wire `ExpertStages.init()` with 8-stage static data from `visualization.html`
- [x] Implement `ExpertPipeline.spawnParticleFromEvent()` driven by SSE `inference` events
- [x] Implement `ExpertPipeline.updateNodeGlow()` driven by poll data
- [x] Implement `ExpertMetrics.updateTrend()` from `if.recent_scores` + `rf.recent_classifications`
- [x] Implement `ExpertMetrics.updateProtoCounts()` from `rf.class_distribution`
- [x] Implement `ExpertMetrics.updateStats()` from `pipeline`, `tea.global`
- [x] Implement `ExpertMetrics.appendLog()` from SSE events + mitigation events
- [x] Remove `visualization.html` (or mark deprecated)
- [x] Write Playwright tests in `test/e2e/` (6 scenarios)
- [ ] Verify UI Slop Score >= 8/10 across all 7 criteria (needs manual visual review)
- [ ] Run lint/typecheck if available (no JS linter configured in project)
- [ ] Update [[frontend/dashboard]] note with final module structure

## Verification

- [ ] Expert Mode toggle shows pipeline canvas + 3 existing panels (needs running app)
- [ ] Clicking canvas nodes updates inspector with correct stage data (needs running app)
- [ ] SSE inference events spawn visible particles on canvas (needs running app)
- [ ] Poll updates metrics, trend SVG, protocol counts without layout shift (needs running app)
- [ ] Zero console errors across all test scenarios (needs running app)
- [ ] Responsive at 1440/768/375px viewports (needs running app)

## Related

- [[frontend/expert-pipeline-visualization]]
