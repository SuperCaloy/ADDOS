---
created: 2026-08-24
last-updated: 2026-08-24
status: done
area: [frontend, ui-ux]
---

# Professional Tone Rewrite: Explanatory Text

## Objective

Rewrite all explanatory text in the IP Details drawer and Expert Mode pipeline visualization to sound more professional while remaining clear and understandable.

**Audience:** Network administrators -- assume technical competence with networking concepts (IPs, ports, protocols, flow rates), but don't assume familiarity with this system's ML pipeline internals (IF/RF/TEA terminology should be briefly explained).

**Tone:** Professional and precise, similar to documentation/UI copy in enterprise network security tools. Avoid overly casual phrasing, but also avoid dense academic/ML jargon.

## Scope

### Files modified

1. `frontend/static/ip-drawer.js` (1051 lines)
   - Feature tooltips (7 items, lines 1-9)
   - Attack descriptions (5 types, lines 11-51)
   - Attack table subtext (15 rows across 5 attack types, lines 11-51)
   - Algorithm Trace section intros (2 intros, lines 959, 974)
   - Algorithm Trace feature descriptions (31 descriptions, lines 898-934)
   - ML threshold labels (4 labels, lines 621-626)
   - Decision trace reasons (4 patterns, lines 1019-1026)

2. `frontend/static/expert.js` (1179 lines)
   - Pipeline stage descriptions (10 stages, lines 166-274)

3. `backend/api/expert.py` (222 lines)
   - No user-facing text (JSON data only) -- not in scope

### Text categories

| Category | Count | Location |
|---|---|---|
| Feature tooltips | 7 | ip-drawer.js:1-9 |
| Attack descriptions | 5 | ip-drawer.js:11-51 |
| Attack table subtext | 15 | ip-drawer.js:11-51 |
| Algorithm Trace intros | 2 | ip-drawer.js:959, 974 |
| Algorithm Trace feature descs | 31 | ip-drawer.js:898-934 |
| ML threshold labels | 4 | ip-drawer.js:621-626 |
| Decision trace reasons | 4 | ip-drawer.js:1019-1026 |
| Pipeline stage descriptions | 10 | expert.js:166-274 |

## Rewrite principles

1. **Professional precision:** Replace casual phrasing ("way more", "a lot of them") with precise technical language ("significantly exceeds", "high aggregate count").
2. **Audience-appropriate:** Assume networking knowledge (IPs, ports, protocols, flow rates). Explain ML-specific terms (IF, RF, TEA) briefly on first use.
3. **Clarity over jargon:** Avoid dense academic/ML terminology. Use enterprise security tool documentation style.
4. **Consistency:** Apply the same tone across all text categories. Use parallel structure for similar items.

## Implementation checklist

- [x] Create plan document
- [x] Rewrite feature tooltips in ip-drawer.js
- [x] Rewrite attack descriptions in ip-drawer.js
- [x] Rewrite attack table subtext in ip-drawer.js
- [x] Rewrite Algorithm Trace section intros in ip-drawer.js
- [x] Rewrite Algorithm Trace feature descriptions in ip-drawer.js
- [x] Rewrite ML threshold labels in ip-drawer.js
- [x] Rewrite decision trace reasons in ip-drawer.js
- [x] Rewrite pipeline stage descriptions in expert.js
- [x] Verify changes (syntax check passed)

## Related notes

- [[notes/ui-ux/]] - UI/UX design decisions
- [[notes/frontend/]] - Frontend architecture
