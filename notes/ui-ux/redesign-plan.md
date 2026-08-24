---
created: 2026-08-20
last-updated: 2026-08-20
status: draft
tags:
  - ui-ux
  - frontend
  - plan
---

# Redesign Plan: Professional Cybersecurity UI/UX

Direction and phased action plan for overhauling the ADDOS dashboard from its current state (see [[ui-ux/ui-ux-audit|UI/UX Audit]]) into a polished, professional enterprise-security interface. Thesis-appropriate: clean, dense, trustworthy, and deliberately not cyberpunk.

## Decisions locked in

- **Accent**: keep teal (`#14B8A6` / `#0D9488`). Brand continuity; already documented as the professional security accent.
- **Typography**: consolidate to **Inter** (UI/labels) + **Fira Code** (data, IPs, metrics). Drop Plus Jakarta Sans, Fira Sans, Source Sans Pro, Space Mono.
- **Technical labels**: `Phase`, `IF score`, `PPS`, attack vectors stay verbatim. These are correct informational content, not aesthetic noise. Only container styling may be softened.
- **Design System file**: `design-system/a-ddos/MASTER.md` stays untouched; this note is the source of truth for the overhaul.
- **Style target**: Data-Dense Dashboard + Minimalism/Swiss. The database "cybersecurity platform" default maps to Cyberpunk UI and is explicitly rejected.

## Design system summary

### Tokens (to be introduced in CSS)

| Group | Token | Value (dark) | Notes |
|-------|-------|--------------|-------|
| Color | keep existing `--bg`/`--surface`/`--card`/`--text`/`--sub`/`--sub2`/`--border`/`--blue`(teal)/`--red`/`--green`/`--amber` | slate navy base | all surfaces must reference vars only, no legacy hex fallbacks |
| Radius | `--radius-sm 6px`, `--radius-md 9px`, `--radius-lg 14px`, `--radius-xl 18px` | | replace hardcoded radii |
| Shadow | `--shadow-sm/md/lg` (subtle, no glow) | | replace hardcoded shadows |
| Focus | `--focus-ring` 2px offset ring in accent | | visible on every interactive control |
| Spacing | reuse `--space-sm..3xl` from MASTER.md | | 8px base grid |

### Typography

- **UI / labels**: Inter (400/500/600/700). Labels 11-12px minimum, uppercase + letter-spacing for section labels only.
- **Data / metrics / IPs / timestamps**: Fira Code (500/700).
- One Google Fonts link loading only these two families. Remove the rest.

### Color semantics (single source, applied everywhere)

- Teal = primary action, links, active state.
- Emerald green = normal/healthy/success/forwarded.
- Amber = warning, quarantine, rate-limit, time-ban, SYN, flash crowd.
- Rose red = critical/anomaly/danger/blocked/ICMP.
- One color per attack class across tags, expert bars, and the drawer. ICMP = red, SYN = amber, UDP = teal, Uncertain = neutral.
- All status colors must pass 4.5:1 on their surface in both themes.

### Icons

- Inline outline SVG only (Lucide/Heroicons/Phosphor), 16-20px, consistent weight.
- Replace `☰ ☀ ☾ ✕ ‹ ›` glyphs. Decorative icons get `aria-hidden="true"`; interactive icons keep visible text labels or `aria-label`.

### Motion

- Hover/active transitions 150-250ms; data bars 300-500ms; no 0ms state flips.
- Wrap all animations in `@media (prefers-reduced-motion: reduce) { * { animation: none; transition: none } }` and give the live chart a Pause control.

## Phased implementation checklist

### Phase 1: Accessibility (do first)

- [x] Add global `:focus-visible` ring on buttons, links, tabs, table rows, calendar cells.
- [x] Remove `outline: none` from `.date-text-input`; use border + ring focus.
- [x] Convert calendar days to `<button>` elements (`ui.js`) with correct semantics.
- [x] Give the IP drawer `role="dialog"`, `aria-modal`, focus move-in, and a focus trap (`ip-drawer.js`).
- [x] Make drawer feature tooltips reachable by keyboard with `aria-describedby`/focus pairing.
- [x] Make table rows keyboard-operable (tabindex + Enter/Space opens the drawer, `main.js`).
- [x] Add `role="status"`/`role="alert"` to toasts (`ui.js`).
- [x] Add `prefers-reduced-motion` guard.
- [x] Bump sub-12px text: calendar weekdays, chart ticks, expert sub-labels to >= 11-12px.

### Phase 2: Performance & data freshness

- [ ] Fix 1s polls: system metrics to 5s, model info to 30s (`dashboard.html`).
- [ ] Fix the range-tab to interval mapping (`1hr/12hr/24hr/session` vs the checked `1h/24h/7d`) in `chart.js`.
- [ ] Keep chart updates on `update('none')` for the live feed.
- [ ] Single font payload: Inter + Fira Code only.

### Phase 3: Style consistency

- [ ] Purge legacy color fallbacks in `ip-drawer.js` and the inline `<style>` in `dashboard.html`; every surface uses the live theme vars.
- [ ] Move the calendar/modal rules out of the inline block into `style.css` so nothing overrides the theme.
- [ ] Theme-map chart colors from CSS vars (including the theme toggle path in `ui.js`).
- [ ] Unify attack-class colors across tags, expert RF bar, and drawer.
- [ ] Remove or reduce the background grid overlay to near-invisible opacity.
- [ ] Standardize on inline SVG icons; remove unicode glyphs.
- [ ] Use `--radius-*`/`--shadow-*` tokens throughout.
- [ ] Wire up the `.status-pill` live "system operational / disconnected" indicator in the header.
- [x] Soften expert terminal container styling; keep the Phase/IF/PPS content verbatim.
- [x] Fix light mode contrast failures (sub2, sub, border, card vs bg) and canvas pipeline visibility.

### Phase 4: Layout & responsive

- [ ] Modal width `min(720px, 92vw)` with no fixed `min-width` that overflows 375px.
- [ ] `.tbl-scroll` horizontal scroll for nowrap tables on small screens.
- [ ] Add breakpoints for 375/660/900/1100/1440; fix header cluster wrapping; shrink `#app` side padding on mobile; stack `.mitigation-phases` to 2 cols below 900px.
- [ ] Touch targets >= 44px for range tabs and action buttons.

### Phase 5: Polish

- [ ] Busy/disabled state on report Generate with a spinner.
- [ ] Confirm dialog before Blackhole.
- [ ] Field-level error styling in the report modal (date range).
- [ ] `aria-live="polite"` on metric cards that update from polls.
- [ ] Chart: optional anomaly-point highlight layer for the thesis narrative (stretch).

## Verification checklist (before calling the overhaul done)

- [ ] Keyboard-only walkthrough: tab order, focus ring visible, calendar pickable, drawer open/close with trap, Esc closes.
- [ ] Screen-reader sanity: toasts announced, drawer announces as dialog, icons ignored when decorative.
- [ ] Both themes at 375 / 768 / 1024 / 1440 px: no horizontal scroll, no clipped tables, modal fits.
- [ ] Contrast spot-check on muted text and status colors in both themes.
- [ ] Reduced-motion: all animations off, live chart static.
- [ ] Backend reachable and unreachable states both render a clear indicator.

## Related notes

- [[ui-ux/ui-ux-audit]]: the findings this plan addresses.
- [[frontend/dashboard]]: module map for where each change lands.
- [[frontend/design-system]]: documented design intent (to be reconciled with this plan).