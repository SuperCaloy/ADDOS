---
created: 2026-08-20
last-updated: 2026-08-20
status: in-progress
area: [frontend]
---

# Task: UI/UX Overhaul

Phased implementation of the dashboard redesign. Design decisions live in [[decisions/ui-ux-direction]]; the full design system and rationale are in [[ui-ux/redesign-plan]]. This file tracks progress only.

## Phase 1: Accessibility (do first)

- [x] Add global `:focus-visible` ring on buttons, links, tabs, table rows, calendar cells.
- [x] Remove `outline: none` from `.date-text-input`; use border + ring focus.
- [x] Convert calendar days to `<button>` elements (`ui.js`) with correct semantics.
- [x] Give the IP drawer `role="dialog"`, `aria-modal`, focus move-in, and a focus trap (`ip-drawer.js`).
- [x] Make drawer feature tooltips reachable by keyboard with `aria-describedby`/focus pairing.
- [x] Make table rows keyboard-operable (tabindex + Enter/Space opens the drawer, `main.js`).
- [x] Add `role="status"`/`role="alert"` to toasts (`ui.js`).
- [x] Add `prefers-reduced-motion` guard.
- [x] Bump sub-12px text: calendar weekdays, chart ticks, expert sub-labels to >= 11-12px.

## Phase 2: Performance & data freshness

- [ ] Fix 1s polls: system metrics to 5s, model info to 30s (`dashboard.html`).
- [ ] Fix the range-tab to interval mapping (`1hr/12hr/24hr/session` vs the checked `1h/24h/7d`) in `chart.js`.
- [ ] Keep chart updates on `update('none')` for the live feed.
- [ ] Single font payload: Inter + Fira Code only.

## Phase 3: Style consistency

- [ ] Purge legacy color fallbacks in `ip-drawer.js` and the inline `<style>` in `dashboard.html`; every surface uses the live theme vars.
- [ ] Move the calendar/modal rules out of the inline block into `style.css` so nothing overrides the theme.
- [ ] Theme-map chart colors from CSS vars (including the theme toggle path in `ui.js`).
- [ ] Unify attack-class colors across tags, expert RF bar, and drawer.
- [ ] Remove or reduce the background grid overlay to near-invisible opacity.
- [ ] Standardize on inline SVG icons; remove unicode glyphs.
- [ ] Use `--radius-*`/`--shadow-*` tokens throughout.
- [ ] Wire up the `.status-pill` live "system operational / disconnected" indicator in the header.
- [ ] Soften expert terminal container styling; keep the Phase/IF/PPS content verbatim.

## Phase 4: Layout & responsive

- [ ] Modal width `min(720px, 92vw)` with no fixed `min-width` that overflows 375px.
- [ ] `.tbl-scroll` horizontal scroll for nowrap tables on small screens.
- [ ] Add breakpoints for 375/660/900/1100/1440; fix header cluster wrapping; shrink `#app` side padding on mobile; stack `.mitigation-phases` to 2 cols below 900px.
- [ ] Touch targets >= 44px for range tabs and action buttons.

## Phase 5: Polish

- [ ] Busy/disabled state on report Generate with a spinner.
- [ ] Confirm dialog before Blackhole.
- [ ] Field-level error styling in the report modal (date range).
- [ ] `aria-live="polite"` on metric cards that update from polls.
- [ ] Chart: optional anomaly-point highlight layer for the thesis narrative (stretch).

## Verification (before calling the overhaul done)

- [ ] Keyboard-only walkthrough: tab order, focus ring visible, calendar pickable, drawer open/close with trap, Esc closes.
- [ ] Screen-reader sanity: toasts announced, drawer announces as dialog, icons ignored when decorative.
- [ ] Both themes at 375 / 768 / 1024 / 1440 px: no horizontal scroll, no clipped tables, modal fits.
- [ ] Contrast spot-check on muted text and status colors in both themes.
- [ ] Reduced-motion: all animations off, live chart static.
- [ ] Backend reachable and unreachable states both render a clear indicator.

## Produced

- [[decisions/ui-ux-direction]]: locked design decisions and reasoning.
- [[ui-ux/redesign-plan]]: design system and source of truth.
- [[ui-ux/ui-ux-audit]]: the findings driving this work.