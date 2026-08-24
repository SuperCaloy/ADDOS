---
created: 2026-08-20
last-updated: 2026-08-20
status: verified
tags:
  - decisions
  - ui-ux
  - frontend
---

# Decision: UI/UX Direction for the Dashboard Overhaul

Why the ADDOS dashboard overhaul targets a professional enterprise-security aesthetic and not the "cyberpunk" HUD look. This is the source of truth for the direction; implementation lives in [[ui-ux/redesign-plan]].

## Context

The dashboard already had a glassmorphism/SOC-style rework (see [[ui-ux/glassmorphism-redesign]]), but an audit found it still drifted toward a sci-fi/HUD feel: blueprint grid overlay at 0.28 opacity, terminal-style expert labeling, unicode glyph icons, and an inconsistent palette ([[ui-ux/ui-ux-audit]]). The thesis defense audience is academic committee members, so credibility and legibility matter more than visual flair.

## Decision

Adopt a Data-Dense Dashboard + Minimalism/Swiss style target. The database's "cybersecurity platform" default (Cyberpunk UI) is explicitly rejected.

Locked in:

- **Accent**: keep teal (`#14B8A6` / `#0D9488`) for brand continuity. Already the documented professional security accent.
- **Typography**: consolidate to **Inter** (UI/labels) + **Fira Code** (data, IPs, metrics). Drop Plus Jakarta Sans, Fira Sans, Source Sans Pro, Space Mono.
- **Technical labels**: `Phase`, `IF score`, `PPS`, and attack vectors stay verbatim. These are correct informational content, not aesthetic noise. Only container styling may be softened.
- **Design System file**: `design-system/a-ddos/MASTER.md` stays untouched; [[ui-ux/redesign-plan]] is the source of truth for the overhaul.

## Reasoning

- **Audience**: committees and security researchers judge density and trustworthiness, not HUD aesthetics.
- **Accessibility baseline**: the audit flagged missing focus rings, non-keyboard calendars, and hover-only tooltips. A professional finish requires WCAG-compliant interaction, which a cyberpunk skin tends to undermine.
- **Data integrity**: attack-class colors must be consistent across surfaces (tags, expert RF bar, drawer), which the legacy palette violated. One color per class reduces operator error.
- **Cost**: consolidating fonts and tokens removes page weight, FOUT, and silent system-font fallbacks, which directly served the audit's performance findings.

## Consequences

- Colors, radii, shadows, and spacing become CSS tokens referenced everywhere; legacy hex fallbacks are purged.
- Charts, toasts, and drawers get theme-mapped vars and proper ARIA/roles.
- A [[tasks/ui-ux-overhaul|task file]] tracks the phased implementation against [[ui-ux/redesign-plan|the redesign plan]].

## Related

- [[ui-ux/redesign-plan]]: the concrete design system and phased checklist.
- [[ui-ux/ui-ux-audit]]: the findings that motivated this direction.
- [[frontend/design-system]]: documented intent to be reconciled with the redesign plan.