---
created: 2026-08-20
last-updated: 2026-08-20
status: verified
tags:
  - ui-ux
  - frontend
  - audit
---

# UI/UX Audit

Full review of the ADDOS frontend dashboard against the [[frontend/design-system|design-system]] intent and professional (non-cyberpunk) security UI best practices. Findings grouped by priority. This note feeds the [[ui-ux/redesign-plan|Redesign Plan]].

## Scope reviewed

- `frontend/templates/dashboard.html` (339 lines)
- `frontend/static/style.css` (585 lines)
- `frontend/static/{api,ui,chart,stats,mitigation,log,main,ip-drawer,expert}.js`
- Reference docs: `design-system/a-ddos/MASTER.md`, `notes/frontend/design-system.md`, `notes/ui-ux/glassmorphism-redesign.md`

## What is already good

- Dark slate/navy theme with semantic status colors, dual light/dark themes with `prefers-color-scheme` + manual toggle.
- Two-tier interface (SOC dashboard + Expert Mode) fits a thesis defense audience.
- Rich per-IP threat drawer with educational attack descriptions, good for committee Q&A.
- DOM-diffing in log/watchlist tables (no flicker), smart-polling concept, direct browser to Flask data flow.
- Metric deltas and model accuracy are color-coded and text-based (not color-only).

## Priority 1: Accessibility (critical)

1. **No visible `:focus-visible` styling.** `.date-text-input` sets `outline: none` with only a border-color change (`style.css:253-259`, `dashboard.html:18-19`). All other interactive controls rely on the default browser ring. Violates WCAG 2.4.7 and the MASTER.md checklist.
2. **Calendar days are `<div onclick>` elements** (`ui.js:153-169`), not keyboard-operable buttons. Tab order skips them entirely.
3. **IP drawer is a modal without dialog semantics.** No `role="dialog"`, no `aria-modal`, no focus trap, focus is not moved in on open (`ip-drawer.js:54-80, 234-273`). Esc-to-close works.
4. **Drawer feature tooltips are hover-only** (`onmouseenter`/`onmouseleave`, `ip-drawer.js:769-795`). No keyboard/focus equivalent, no `aria-describedby`.
5. **No `prefers-reduced-motion` support anywhere**, despite the MASTER.md checklist claiming it. Blink, rowIn, tin, pulse, and chart animations ignore the setting.
6. **Unicode glyphs used as icons**: `☰ Expert`, `☀ Light Mode`, `☾ Dark Mode`, close `✕`, calendar `‹ ›` (`dashboard.html:63-65`, `ip-drawer.js:102`). Inconsistent rendering across platforms; not a consistent SVG set.
7. **Table rows are mouse-only clickable** (`main.js:15-26`). `<tr>` is not focusable, so keyboard users cannot open the IP drawer.
8. **Toasts have no `role="status"`/`role="alert"`** and no `aria-live` (`ui.js:38-45`). Screen readers never announce actions.
9. **Text below the 12px body floor**: calendar weekday labels at 10px (`dashboard.html:34`), chart ticks at 9px (`chart.js:48-49`), expert sub-labels at 9-10px (`style.css:519`). Small muted text on dark surfaces risks falling under 4.5:1.

## Priority 2: Touch & interaction

10. **Touch targets below 44px**: range tabs `padding: 5px 13px` (~27px tall, `style.css:162`), watchlist action buttons `padding: 5px 14px` (~26px, `style.css:229`).
11. **No connection/loading state.** All fetch catches silently swallow errors, so a dead backend renders as persistent zeros. The `.status-pill` component exists exactly for this (`style.css:121-128`) but is **dead code**.
12. **Report Generate has no busy/disabled state** (`ui.js:92-120`) → double-click fires duplicate PDF requests.

## Priority 3: Performance

13. **Polling mismatch and over-polling**: `dashboard.html:333-334` runs `fetchSystemMetrics()` and `pollModelInfo()` every **1 second** despite comments claiming 5s/30s. Model accuracy changes rarely; 1s polling wastes backend and DB work.
14. **Five font families referenced, only three loaded** (`style.css:1` Plus Jakarta Sans + Fira Code; `dashboard.html:7` Fira Sans + Fira Code; `style.css:148-150` Source Sans Pro never loaded; `chart.js:25,34` Space Mono never loaded). Extra page weight + FOUT + inconsistent rendering.

## Priority 4: Style consistency (the biggest source of an unpolished feel)

15. **Legacy color fallbacks everywhere.** `var(--blue,#3d6cff)`, `var(--red,#ff3d5a)`, `var(--green,#00d68f)`, `var(--card,#13162a)`, `var(--sub,#5c6080)` in the drawer (`ip-drawer.js`, dense) and in the inline `<style>` block (`dashboard.html:10-51`). These are the old palette; when a theme var is missing they render colors that clash with the current teal/rose/emerald theme.
16. **Inline `<style>` overrides the theme CSS.** The calendar + modal rules in `dashboard.html:10-51` load after `style.css` and win, so those components do not track the real theme variables.
17. **Chart colors hardcoded** `#3d6cff` / `#ff3d5a` / `#00d68f` (`chart.js:13-15`), and the theme toggle updates them with hardcoded light/dark hexes (`ui.js:57-71`) that also do not match the CSS palette.
18. **Attack-class colors disagree across surfaces.** ICMP is red in tags (`style.css:215`), pink `#f472b6` in the expert RF bar (`expert.js:166`), red in the drawer (`ip-drawer.js:13`). UDP is teal in tags, light blue `#60b4ff` in the expert bar, amber in the drawer. One class should have one color.
19. **Blueprint background grid at 0.28 opacity** (`style.css:95-105`) reads sci-fi/HUD. For a professional thesis dashboard it should be removed or reduced to near-invisible.
20. **Expert Mode terminal labeling** (`PHASE_1`, `IF=`, `PPS=`, `ACT=`, `TTL=`, `expert.js:317-322`) reads like a hacker console. Decision: content is informational and stays verbatim (Phase, IF score, PPS are correct thesis terminology); only the container styling may be softened.
21. **Icon set is inconsistent**: one SVG (calendar, good) + five unicode glyphs. `.status-pill` unused.

## Priority 5: Layout & responsive

22. **Report modal `min-width: 620px`** (`dashboard.html:12`) overflows on mobile (375px) → horizontal scroll, violating the no-horizontal-scroll rule.
23. **Tables are `white-space: nowrap` with vertical-only scroll** (`style.css:190,205`) → columns clip on small screens with no way to reach them.
24. **Only two breakpoints** (1100/660px, `style.css:300-301`). The header button cluster and the 4-column `.mitigation-phases` row (`style.css:386`) break awkwardly in the 660-1100 range; `#app` keeps 36px side padding on mobile (`style.css:107`).

## Priority 6-10: Minor

25. **Radii/shadows hardcoded** (6-18px across the file). The `--shadow-*` and spacing tokens in MASTER.md are never consumed.
26. **Smart-polling range mapping bug**: tabs are `Live/1hr/12hr/24hr/Session` but `chart.js:102-105` checks `1h/24h/7d` → interval always falls back to 10s.
27. **Metric cards use `Source Sans Pro`** (`style.css:148-150`), never loaded → silent system-font fallback, inconsistent with the rest.
28. **No confirmation on destructive Blackhole action** (`mitigation.js:86-97`): one-click permanent-block.
29. **Report modal has no error styling on the date fields themselves**; only a shared error line (`ui.js:97-99`).

## Related notes

- [[ui-ux/redesign-plan]]: the design system and phased fix plan.
- [[ui-ux/glassmorphism-redesign]]: previous overhaul that introduced the current aesthetic.
- [[frontend/dashboard]]: architecture and module map.
- [[frontend/design-system]]: the documented design intent this audit compares against.