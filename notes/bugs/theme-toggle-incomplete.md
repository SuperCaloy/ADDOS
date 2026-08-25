---
created: 2026-08-23
last-updated: 2026-08-23
status: verified
---

# Theme toggle requires manual page refresh

## Symptom

Switching between Light Mode and Dark Mode via the header button did not fully apply the new theme. Some UI elements retained the previous theme's styling until a manual page reload. The toggle worked inconsistently in both directions.

## Root causes

Three distinct bugs:

### 1. CSS `@media (prefers-color-scheme: light)` vs manual toggle conflict

`style.css:32-56` defined a `@media (prefers-color-scheme: light)` block that overrides `:root` CSS variables when the OS is in light mode. The manual toggle only added/removed `body.light`. There was no `body.dark` class to force dark mode when the OS prefers light.

Result: if the OS was in light mode and the user clicked "Dark Mode", the media query kept forcing light colors on `:root`. The toggle worked in one direction but not the other, depending on OS setting.

### 2. `ExpertPipeline.isLightMode` set once, never updated

`expert.js:353-354` read `document.body.classList.contains('light')` once during `ExpertPipeline.init()`. When `toggleTheme()` ran, it never updated `ExpertPipeline.isLightMode`, so the pipeline canvas kept using stale colors from the previous theme.

### 3. Hardcoded table hover color

`style.css:206` had `tbody tr:hover { background: rgba(255,255,255,.018); }` which is invisible on light backgrounds.

## Fix

### style.css

- Added `body.dark` class with the same dark-mode variable values as `:root`, so it overrides the `@media (prefers-color-scheme: light)` block when the user explicitly chooses dark mode.
- Changed table hover to `rgba(128,128,128,.06)` which is visible in both themes.
- Bumped cache-bust to `v=9`.

### ui.js

- Extracted theme application into `_applyTheme(light)` which toggles both `body.light` and `body.dark` classes.
- Added `window.ExpertPipeline.isLightMode = light` update inside `_applyTheme()`.
- On `DOMContentLoaded`, always call `_applyTheme()` to set the correct `body.dark`/`body.light` class, even when no saved preference exists.

## Files changed

- `frontend/static/style.css` (added `body.dark`, fixed hover color, v=9)
- `frontend/static/ui.js` (refactored toggle, sync ExpertPipeline, v=9)
- `frontend/templates/dashboard.html` (cache-bust v=8 to v=9)

## Related

- [[frontend/light-mode-accessibility]]
- [[ui-ux/ui-ux-audit]]
