---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - ui-ux
  - frontend
---

# UI/UX Glassmorphism Redesign

> [!warning] Deprecated
> This describes the earlier SOC aesthetic that the professional redesign supersedes on 2026-08-20. See [[ui-ux/redesign-plan]] for the current direction and [[decisions/ui-ux-direction]] for the reasoning.

The frontend dashboard of the ADDOS thesis project was overhauled to use a modern **Glassmorphism** design system, tailored for a Security Operations Center (SOC) aesthetic.

## Rationale
- **Target Audience**: Security Researchers, NOC Analysts, and Academic Committees. 
- **Goal**: Provide an instantly credible, highly technical interface focused on situational awareness rather than raw data dumps.

## Key Changes
1. **Typography**: Changed from `Space Mono` / `DM Sans` to `Fira Code` (for metrics and IPs) and `Fira Sans` (for UI labels).
2. **Colors**: 
   - Background: Deep Slate (`#0F172A`)
   - Cards: Glassy Navy (`rgba(27, 35, 54, 0.7)`) with a 12px `backdrop-filter: blur()`.
   - Status: Standardized to Green (`#22C55E`) for normal/success, and Red (`#EF4444`) for critical anomalies.
3. **Data Aggregation & Visualizations (SOC Redesign)**:
   - **Grid Layout**: The Expert Tab was updated to use a side-by-side CSS grid (`1fr 1fr`), placing ML Internals on the left and Mitigation on the right.
   - **Isolation Forest Threat Level**: Converted the raw data lists into an aggregated, animated "Threat Level" gauge plotting the highest current score against the threshold limit.
   - **Random Forest Composition**: Replaced lists with a single segmented progress bar showing the percentage split between Normal, SYN, ICMP, and UDP traffic.
   - **TEA Entropy**: Aggregated individual switches into a Controller Global Entropy panel. The CSS was updated to animate the Z-Score bars smoothly in-place every 2 seconds without DOM destruction.
   - **Terminal-Style Feeds**: Replaced table layouts in the active threats and sinkhole lists with scrollable, dark `terminal-feed` panels featuring monospace fonts and tick-up progress bars for sinkholes.
4. **Logic & Bug Fixes**:
   - **Live Traffic Monitor**: The historical tabs (`1 hr`, `12 hr`, `24 hr`, `Session`) were static snapshots that glitched when the 1-second live feed appended to them. We added a background interval (`_historyTimer`) that pauses the live feed and smoothly fetches the DB history every 10 seconds when viewing those tabs.
   - **Audit Log Expert Event Bug**: Fixed a bug where `backend/api/events` was sending new `expert` events into the SSE stream. `log.js` was blindly parsing them, failing to find an IP, and rendering empty dashes `-`. We added logic in `log.js` to ignore `expert` event types.

## Related Files
- `frontend/static/style.css`
- `frontend/static/expert.js`
- `frontend/static/chart.js`
- `frontend/static/log.js`
- `frontend/templates/dashboard.html`
