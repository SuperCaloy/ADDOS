---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
---

# UI/UX Design System: Enterprise Security Dashboard

> [!note]
> The [[ui-ux/redesign-plan]] supersedes the typography and palette specifics below (Inter + Fira Code only, teal accent). This note documents the original intent; see [[decisions/ui-ux-direction]] for the locked decisions.

This document tracks the overarching UI/UX philosophy and concrete design system implementation for the ADDOS frontend dashboard.

## Design Philosophy

The dashboard is designed for Network Administrators and Security Operations Center (SOC) analysts.
- **Core Values**: Trust, clarity, high data density, accessibility, and low eye-fatigue (for long monitoring shifts).
- **Aesthetic**: Enterprise Professional, steering entirely clear of "hacker/cyberpunk" tropes.

## Dual-Theme Architecture (Light/Dark Mode)

The UI fully supports system-level `prefers-color-scheme` switching.

### Semantic Color Palette

| Usage | Dark Mode (Default) | Light Mode | Notes |
| :--- | :--- | :--- | :--- |
| **Background** | Deep Slate (`#0F172A`) | Crisp Slate-Gray (`#F8FAFC`) | Reduces eye strain over pure black/white |
| **Surfaces/Cards** | Elevated Slate (`#1E293B`) | Clean White (`#FFFFFF`) | Distinguishes content regions |
| **Text (Primary)** | Off-white (`#F8FAFC`) | Deep Navy (`#0F172A`) | High contrast legibility (WCAG AA+) |
| **Text (Muted)** | Light Slate (`#CBD5E1`) | Slate (`#475569`) | Increased contrast to prevent blending |
| **Primary/Action** | Teal (`#14B8A6`) | Deep Teal (`#0D9488`) | Professional security accent, high visibility |
| **Success/Normal** | Emerald (`#10B981`) | Forest Green (`#059669`) | System healthy, no alerts |
| **Alert/Danger** | Accessible Rose (`#E11D48`) | Cardinal Red (`#BE123C`) | Flash crowds, attacks, critical state |

## Typography & Contrast Improvements

- **UI & Labels**: `Plus Jakarta Sans` or `Inter`. Provides a clean, modern, B2B SaaS feel with excellent legibility.
- **Contrast Guardrails**: Muted text in Dark Mode has been brightened from Slate-500 (`#64748B`) to Slate-300 (`#CBD5E1`) to strictly prevent text from blending into the Dark Slate (`#1E293B`) cards.
- **Data & Metrics**: `Fira Code` (Monospace). Used strictly for raw data readouts, IP addresses, and the TEA variance widget to ensure numeric alignment and technical precision.
- **Formatting**: Values use heavy weights (`font-weight: 600`), while labels use lighter weights (`font-weight: 400`).

## UI Components & Data Presentation

- **Badges/Cards**: No heavy drop shadows or excessive glassmorphism. We rely on clean 1px borders and subtle background tints (`rgba()`) for component elevation.
- **Component Semantic Adjustments**: Several components (Grid Opacity, Terminal Feed Background, Z-Score Tracks) utilize dynamic CSS variables (`--grid-opacity`, `--terminal-bg`, `--track-bg`) specifically to soften harsh lines and maintain high readability when flipping to Light Mode.
- **Density**: Fractional metrics (like Temporal Entropy Analysis variance) are natively truncated to exactly 4 decimal places in the frontend (`.toFixed(4)`) to minimize visual noise while retaining statistical significance.

## Smart Polling Engine (Performance)

To maintain a "Live" feel without overwhelming the backend and database, the dashboard utilizes dynamic `setInterval` polling that scales back as the time horizon increases:
- **Live**: ~2 seconds (or SSE).
- **1 Hour Chart**: 30 seconds.
- **24 Hour Chart**: 5 minutes.
- **7 Day Chart**: 30 minutes.
