---
created: 2026-08-21
last-updated: 2026-08-21
status: verified
tags:
  - frontend
  - expert-mode
  - visualization
  - canvas
---

# Expert Pipeline Visualization

**Source:** `visualization.html` (784 lines, standalone at repo root)
**Target:** `frontend/static/expert.js` (namespaced sections within existing module)
**Spec:** `docs/superpowers/specs/2026-08-21-expert-pipeline-visualization-design.md`

## What it is

An interactive canvas-based visualization of the ADDOS 8-stage detection pipeline, integrated into the dashboard's Expert Mode. Replaces the hardcoded simulation in `visualization.html` with real backend data.

## Architecture

### Namespaced sections in expert.js

| Namespace | Responsibility |
|---|---|
| `ExpertState` | Shared mutable state: selectedStage, histories, counts |
| `ExpertStages` | Static stage data (8 stages), inspector DOM updates |
| `ExpertPipeline` | Canvas rendering, particles, node glow, resize handling |
| `ExpertMetrics` | Trend SVG, protocol counts, terminal log, stats row |

### Data flow

- **SSE `/api/events`** (type: `expert`, payload: `inference`) drives particle animation through the canvas pipeline
- **Poll `/api/expert/live`** (every 2s) drives node glow intensity, trend SVG, protocol counts, stats, terminal log
- **Existing panels** (ML Internals, Mitigation State Machine) remain unchanged below the new pipeline panel

### What was removed

- `setTrafficMode()` + setTimeout attack simulation chain
- `mitigateAttack()` + `resetMitigation()`
- Mode toggle buttons (Normal/Attack)
- All global mutable state variables
- 264 lines of inline CSS (moved to `style.css` under `.expert-pipeline-*`)

### CSS migration

Inline styles from `visualization.html` moved to `style.css`:
- `.canvas-shell` becomes `.expert-pipeline-canvas`
- `.panel` / `.panel-frame` becomes `.expert-inspector`
- `.metric` becomes `.expert-metric`
- `#terminal-logs` becomes `.expert-terminal`
- Colors reuse dashboard tokens: `--bg`, `--surface`, `--text`, `--blue`, `--red`, `--green`, `--amber`

### Dashboard HTML

New panel inserted above existing `#expert-panels` grid:

```html
<div id="expert-pipeline-panel" class="expert-panel expert-hidden">
  <div class="expert-pipeline-canvas-wrap">
    <canvas id="expert-pipeline-canvas"></canvas>
  </div>
  <div class="expert-inspector-row">
    <div id="expert-stage-inspector"></div>
    <div id="expert-live-metrics"></div>
  </div>
</div>
```

## Stage data (static, educational)

The 8 pipeline stages and their descriptions are preserved verbatim from `visualization.html` lines 407-489. Each stage has: num, color, title, file path, description, input, output, optional formula.

| # | Stage | File |
|---|---|---|
| 1 | Mininet Network Topology | `topology/topology.py` |
| 2 | Ryu SDN Controller | `controller/ryu_controller.py` |
| 3 | ZeroMQ Transport | `backend/transport/zmq_receiver.py` |
| 4 | Flood Prefilter | `backend/pipeline/flood_prefilter.py` |
| 5 | Entropy Analyzer (TEA) | `backend/pipeline/entropy_analyzer.py` |
| 6 | Isolation Forest | `backend/models/if_pipeline.py` |
| 7 | Random Forest | `backend/models/rf_pipeline.py` |
| 8 | Decision + Mitigation | `backend/pipeline/decision_engine.py` |

## Test strategy

Playwright MCP tests in `test/e2e/`. Six scenarios: toggle/render, inspector interaction, real-time ingestion, SSE particles, responsive layout, console error monitoring. See spec doc for full details.

## UI Slop Score

Pre/post implementation scoring across 7 criteria (layout shift, spatial consistency, card density, visual hierarchy, color discipline, DOM efficiency, animation restraint). See spec doc for rubric.

## Light Mode Support

Canvas pipeline uses conditional colors based on `isLightMode` flag (set in `ExpertPipeline.init()`). Light mode uses darker paths, strokes, and labels for visibility on white backgrounds. See [[frontend/light-mode-accessibility]] for full details.

## Related notes

- [[frontend/dashboard]]: module map and Expert Mode integration
- [[frontend/design-system]]: design tokens and theme architecture
- [[frontend/light-mode-accessibility|Light Mode Accessibility]]: WCAG AA contrast fixes and canvas light mode logic
- [[backend/expert-api]]: `/api/expert/live` schema and SSE event format
- [[ui-ux/redesign-plan]]: phased overhaul this work feeds into
