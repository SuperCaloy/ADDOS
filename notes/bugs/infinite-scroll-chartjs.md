---
created: 2026-08-19
last-updated: 2026-08-19
status: verified
tags:
  - bugs
  - frontend
  - chartjs
---

# Chart.js Infinite Scroll Bug

> [!note]
> This layout bug was fixed on 2026-08-19.

## Description
Opening the Expert Mode panels (`#expert-panels`) on the frontend dashboard caused an infinite resize loop, resulting in a massive amount of empty scrolling space below the content (endlessly stretching the grid background).

## Root Cause
The `<canvas>` elements for the Chart.js sparklines (`#latency-sparkline` and `#tea-spark-dpid`) were injected directly into parent containers (`.ml-section` and `.tea-switch-card`) with the Chart.js option `maintainAspectRatio: false`.
Because the parent containers did not have a strict height constraint, Chart.js would read the parent's height, apply it, which would trigger the parent to grow, which would trigger Chart.js to resize again in an infinite loop.

## Fix
1. Wrapped every Chart.js `<canvas>` in a dedicated `<div>` wrapper.
2. Applied `position: relative` and a fixed `height` (e.g., `50px` or `60px`) to the wrapper via CSS (`.latency-sparkline-wrap`, `.tea-sparkline-wrap`).
3. Removed the CSS height classes directly from the `<canvas>` elements themselves so Chart.js automatically fills the relative wrapper without looping.

Additionally, `#expert-panels` was moved inside the `#app` layout container in `dashboard.html` to inherit the global `1600px` max-width and `80px` bottom padding.

## Related Notes

- [[frontend/dashboard]]: dashboard layout and components
- [[bugs/missing-expert-button-css]]: related CSS fix for expert panel
