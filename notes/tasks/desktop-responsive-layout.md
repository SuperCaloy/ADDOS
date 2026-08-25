---
created: 2026-08-24
last-updated: 2026-08-24
status: done
area: [frontend]
---

# Task: Desktop Responsive Layout

Make the frontend fully responsive across desktop-class screen sizes: small laptops (1366x768), standard laptops (1440x900 / 1536x864), and larger desktop monitors (1920x1080, 2560x1440). Includes VM environments with non-standard DPI/scaling.

**Out of scope:** mobile and tablet responsiveness.

**Related:** [[ui-ux-overhaul]] Phase 4 covers mobile breakpoints (375-1440px). This task focuses on the desktop range that Phase 4 does not address.

## Current State

Investigated `style.css` (1019 lines) and `dashboard.html`. Key findings:

- `#app` container: `max-width: 1600px`, centered, `padding: 0 36px 80px`
- `.perf-row`: hardcoded `280px` left column
- `.modal`: `min-width: 620-640px` (inline style in dashboard.html)
- Tables: `white-space: nowrap` on all cells, no horizontal overflow guard on the panel itself
- Header: no `flex-wrap`, buttons can crowd at narrow widths
- Chart: fixed `height: 240px`
- Only 2 responsive breakpoints exist (1100px, 660px), both mobile-oriented
- No breakpoints for large screens (1920+, 2560+)
- All font sizes are fixed `px`, no scaling for high-DPI or large monitors

## Implementation

### Step 1: Container and base scaling

- [x] Change `#app` from `max-width: 1600px` to `max-width: clamp(1200px, 90vw, 2200px)` so content scales on large monitors
- [x] Reduce side padding at narrower widths: add `padding: 0 20px 60px` at `<=1366px`
- [x] Bump base `font-size` at `>=1920px` (15px to 16px) and `>=2400px` (16px to 17px)

### Step 2: Header wrapping

- [x] Add `flex-wrap: wrap` and `gap: 12px` to `header` so buttons wrap below the logo at narrow widths
- [x] Ensure `.header-right` also wraps gracefully

### Step 3: Perf-row flex fix

- [x] Change `.perf-row` grid from `280px 1fr` to `minmax(220px, 25%) 1fr` so the resource card flexes
- [x] Verify `.perf-subgrid` still renders 2x2 at all desktop widths

### Step 4: Modal overflow fix

- [x] Remove `min-width: 620px` from inline style in `dashboard.html`
- [x] Change `.modal` to `width: min(640px, 90vw)` in `style.css`
- [x] Ensure modal content does not overflow horizontally at 1366px

### Step 5: Table overflow guards

- [x] Add `overflow-x: auto` to `.panel` or wrap `.tbl-scroll` so 7-column tables do not force page-level horizontal scroll
- [x] At `<=1366px`, allow table cells to wrap (`white-space: normal`) on non-critical columns (Timestamp, Attack Vector) to preserve readability
- [x] Ensure `.tbl-scroll` `max-height` still works with the overflow guard

### Step 6: Chart height

- [x] Change `.chart-wrap` height from fixed `240px` to `height: clamp(200px, 25vh, 300px)`

### Step 7: Large screen breakpoints

- [x] At `>=1920px`: widen container, bump body font to 16px, increase `.m-value` to 38px
- [x] At `>=2400px`: further widen, bump body font to 17px, increase spacing/gaps slightly

### Step 8: Small desktop breakpoint (1366px)

- [x] At `<=1366px`: cards-grid stays 4-col but with tighter padding (`20px 22px 18px` on `.metric-card`)
- [x] At `<=1366px`: reduce `.m-value` font-size to 28px
- [x] At `<=1280px`: cards-grid to 2-col (move existing 1100px breakpoint up)

### Step 9: Expert panels at desktop widths

- [x] Verify `#expert-panels` 2-col grid works at 1366px (each panel gets ~620px)
- [x] Verify `.expert-inspector-row` grid works at all desktop widths
- [x] Verify pipeline canvas `clamp(380px, 50vh, 520px)` renders correctly at 768px viewport height

## Verification

Test each breakpoint in both dark and light mode.

- [x] **1366x768:** No horizontal scroll. Header wraps. Cards readable. Tables do not overflow. Modal fits.
- [x] **1440x900:** All panels render without crowding. Perf-row resource card proportional.
- [x] **1536x864:** Same as 1440, confirm no regressions.
- [x] **1920x1080:** Container uses available width. Font sizes comfortable. No excessive whitespace.
- [x] **2560x1440:** Container scales up. Text remains legible. No stretched/ugly gaps.
- [x] **VM DPI scaling (125%):** Effective viewport ~1092x614 at 2560x1440 with 125%. Confirm layout holds.
- [x] **Expert Mode on at each breakpoint:** Pipeline canvas, ML Internals, Mitigation State Machine all render without overflow or clipping.
- [x] **Both themes at each breakpoint:** No color/contrast regressions from the layout changes.

## Files Changed

- `frontend/static/style.css` (media queries, container, perf-row, modal, chart, font scaling)
- `frontend/templates/dashboard.html` (remove inline `min-width` on modal)
