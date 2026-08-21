---
title: Expert Pipeline Visualization - Modular Architecture Design
created: 2026-08-21
status: approved
area: [frontend, ui-ux, testing]
---

# Expert Pipeline Visualization: Modular Architecture Design

## Overview

This document specifies the extraction and modularization of the interactive pipeline visualization from `visualization.html` (784 lines, monolithic) into the existing `frontend/static/expert.js` module, integrated into the main dashboard as an Expert Mode panel.

**Key decisions:**
- Replace hardcoded simulation with real backend data (`/api/expert/live`, SSE `/api/events`)
- Use namespaced sections within `expert.js` (Approach A) to match existing codebase patterns
- Hybrid canvas animation: SSE inference events drive particles, polling drives node glow
- Preserve existing 3 Expert Mode panels (ML Internals, Mitigation State Machine, TEA) alongside new canvas

## 1. Modular Architecture

### What gets removed from visualization.html

| Removed | Reason |
|---|---|
| `setTrafficMode()` + setTimeout chain (lines 581-636) | Hardcoded simulation replaced by real SSE/poll data |
| `mitigateAttack()` (lines 638-652) | Real mitigation comes from backend state_machine |
| Mode toggle buttons (Normal/Attack) | No manual simulation control |
| `resetMitigation()` button | No simulation to reset |
| Global mutable state (`currentMode`, `mitigationApplied`, `ppsRate`, etc.) | Replaced by `ExpertState` object fed by backend |
| Standalone `<style>` block (264 lines) | CSS moves to `style.css` under `.expert-pipeline-*` namespace |

### What gets preserved and modularized

| Preserved | Becomes | Data source |
|---|---|---|
| `stageData` object (8 stages) | `ExpertStages.data` | Static educational content |
| Canvas node/path/particle rendering | `ExpertPipeline` namespace | SSE events drive particles; poll drives glow |
| Stage inspector (click node) | `ExpertStages.updateInspector(key)` | Static data + live overlay from `/api/expert/live` |
| Trend SVG (IF/RF lines) | `ExpertMetrics.trend` | Poll: `if.recent_scores`, `rf.recent_classifications` |
| Protocol counts (SYN/ICMP/UDP) | `ExpertMetrics.proto` | Poll: `pipeline.flood_prefilter_flagged` + `rf.class_distribution` |
| Terminal log | `ExpertMetrics.log` | SSE `expert` events + mitigation events |
| Metrics row (PPS, entropy, verdict) | `ExpertMetrics.stats` | Poll: `pipeline`, `tea.global`, `if.recent_scores` |

### New expert.js structure (namespaced)

```
expert.js (~650 lines):

  ExpertState {}           - shared state: mode, selectedStage, histories, counts
  ExpertStages             - .data (8 stages), .updateInspector(key), .init()
  ExpertPipeline           - .canvas, .ctx, .nodes, .paths, .particles[]
                           - .init(container), .resize(), .drawScene()
                           - .spawnParticleFromEvent(ssePayload)
                           - .updateNodeGlow(pollData)
  ExpertMetrics            - .updateTrend(ifScores, rfConfs)
                           - .updateProtoCounts(prefilterFlagged, rfDist)
                           - .updateStats(pipeline, tea, if)
                           - .appendLog(text, type)
                           - .clearLog()
  (existing code)          - toggleExpertMode, renderMLPanel, renderMitigationPanel
  (orchestrator)           - startExpertMode: init canvas, connect SSE, start poll
                           - handleExpertEvent: route SSE to Pipeline + Metrics
                           - fetchExpert: poll /api/expert/live, route to Metrics + Pipeline.glow
```

### CSS migration

264 lines of inline CSS move to `style.css` under `.expert-pipeline-*` namespace. Key mappings:

- `.canvas-shell` becomes `.expert-pipeline-canvas`
- `.panel` / `.panel-frame` becomes `.expert-inspector`
- `.metric` / `.proto-item` becomes `.expert-metric` / `.expert-proto-item`
- `#terminal-logs` becomes `.expert-terminal`
- Colors reuse existing dashboard vars: `--bg`, `--surface`, `--card`, `--text`, `--blue`, `--red`, `--green`, `--amber`

### Dashboard HTML changes

New top panel in Expert Mode section:

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

Existing `#expert-panels` grid (ML + Mitigation) moves below this.

## 2. Playwright MCP Test Strategy

### Test environment

- Frontend: `http://127.0.0.1:8080`, Backend: `http://127.0.0.1:5000`
- Test files: `test/e2e/`
- Each test starts with Expert Mode toggled on

### Test scenarios

**Scenario 1: Expert Mode toggle and panel rendering**
1. Navigate to `/` -- no console errors
2. Click Expert Mode -- `#expert-pipeline-panel` visible, canvas has dimensions
3. Verify 8 stage nodes via `page.evaluate(() => Object.keys(ExpertPipeline.nodes).length)`
4. Existing 3 panels render (`#expert-ml-content`, `#expert-mitigation-content` non-empty)

**Scenario 2: Stage inspector interaction**
1. Click canvas near "Mininet" node -- inspector shows "Mininet Network Topology"
2. Click "Isolation Forest" node -- formula block visible
3. Click "Decision + Block" -- stage 8, file contains `decision_engine.py`
4. I/O columns populated with non-empty text

**Scenario 3: Real-time data ingestion**
1. Enable Expert Mode, wait 3s -- `/api/expert/live` fetched (intercept network)
2. Metrics show valid values (PPS, entropy)
3. Trend SVG has non-empty `points` after 2+ polls
4. Terminal log has timestamped entries

**Scenario 4: SSE-driven particle animation**
1. Enable Expert Mode -- `ExpertPipeline.particles` starts empty
2. Wait for SSE `inference` event -- particles array grows within 5s
3. Wait 2s -- particle progress advances

**Scenario 5: Responsive layout**
1. Viewport 1440x900 -- canvas + inspector side by side
2. Viewport 768x1024 -- panels stack, canvas resizes
3. Viewport 375x812 -- no horizontal scroll

**Scenario 6: Console error monitoring (all scenarios)**
- Zero JS errors via `page.on('pageerror')`
- Zero uncaught exceptions via `page.on('error')`
- No 404/500 on `/api/*` routes via `page.on('response')`

## 3. UI Slop Assessment Framework

### UI Slop Score (1-10)

| Criterion | Weight | 10/10 | 1/10 |
|---|---|---|---|
| Layout shift prevention | 20% | Metrics update via textContent, no reflow | Elements jump on data arrival |
| Spatial consistency | 20% | Fixed grid cells, token-based padding | Panel sizes change with content |
| Card padding and density | 15% | Uniform --space-md, equal min-height | Uneven padding, wrapping values |
| Visual hierarchy | 15% | Canvas dominant, inspector secondary, metrics tertiary | Everything competes for attention |
| Color discipline | 10% | All CSS vars, semantic stage colors | Hardcoded hex, theme mismatch |
| DOM efficiency | 10% | Log capped at 50, trend at 60 points | Unbounded growth |
| Animation restraint | 10% | Subtle particles, reduced-motion support | Flashing, explosions |

### Pre-implementation rules

1. No new CSS files. All styles in `style.css` under `.expert-pipeline-*`.
2. No inline styles in JS (except canvas ctx calls).
3. All colors/radii/shadows/spacing reference existing `--var` tokens.
4. Cap all lists: terminal log 50, trend SVG 60 points, history arrays 60.
5. Single `<canvas>` element. No secondary canvases or SVG overlays.
6. No new dependencies. Canvas 2D + requestAnimationFrame only.
7. DOM-diff for metrics: `textContent` on existing elements, no `innerHTML` replacement.
8. CSS grid for layout with fixed `grid-template-columns`.
