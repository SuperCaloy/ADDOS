---
created: 2026-08-23
last-updated: 2026-08-25
status: verified
---

# Project Index

## Folders

- [[backend/]] - Backend architecture and API design
- [[bugs/]] - Bug reports and root cause analysis
- [[config/]] - Configuration management and settings
- [[controller/]] - Controller layer implementation
- [[decisions/]] - Architectural and design decisions with rationale
- [[frontend/]] - Frontend architecture and UI components
- [[known-issues/]] - Known issues and anomaly detection research
- [[mitigation/]] - Mitigation system fixes and behavioral scoring
- [[overview/]] - Architecture and project overview
- [[research/]] - Literature research and benchmark precedents
- [[tasks/]] - Implementation plans and task tracking
- [[topology/]] - Network topology and system mapping
- [[ui-ux/]] - UI/UX design guidelines and patterns

## Key Notes

### Active Regression Plan

- [[tasks/regression-fix-plan-2026-08-24]] - Priority-ordered fix plan for all known system regressions (P0 through P10)

### Research

- [[research/simulation-duration-and-metric-thresholds]] - Literature-grounded simulation duration and SOP 1 / SOP 2 metric targets with citations

### Backend

- [[backend/tea-analysis]] - TEA entropy detection design
- [[backend/mitigation]] - State machine phases and lifecycle
- [[backend/database]] - Schema and writer design
- [[backend/api]] - REST and SSE API endpoints

### Bugs

- [[bugs/reputation-scoring-stalled]] - P0 root cause: reputation/offenses zeroing
- [[bugs/audit-log-re-attack-update]] - P3 context: audit log SSE on phase transitions
- [[bugs/tea-attacks-flagged-as-normal]] - P5 context: TEA entropy misclassification
- [[bugs/ban-lifecycle-loop]] - Ban expiry stale state
- [[bugs/attack-detection-dropoff]] - Detection drop-off over time
- [[bugs/tea-if-feedback-loop-missing]] - TEA output has no pipeline effect
- [[bugs/tea-bar-layout-and-ip-drawer]] - TEA bar and IP drawer layout
- [[bugs/ip-details-zero-values]] - IP details zero reputation/offences
- [[bugs/expert-mode-flow-reading-bug]] - Expert mode flow reading
- [[bugs/expert-attribute-error]] - Expert API crash
- [[bugs/missing-expert-button-css]] - Missing expert button CSS
- [[bugs/infinite-scroll-chartjs]] - Infinite scroll ChartJS issue
- [[bugs/theme-toggle-incomplete]] - Theme toggle incomplete
- [[bugs/unscored-hold-blackhole-bypass]] - P11: unscored hold bypasses reputation threshold
- [[bugs/detection-dropoff-after-ban-expiry]] - P12: detection drop-off after ban expiry
- [[bugs/reputation-blackhole-bypass]] - P13: reputation >= 10 not triggering blackhole
- [[bugs/attacker-count-dropoff]] - P14: only 15-18 attackers detected instead of 20
- [[bugs/offence-counter-bug-fix]] - Offence counter incrementing on every scoring cycle instead of per re-offence
- [[bugs/expert-mode-freeze-regression]] - Expert Mode freeze after TEA verdict fix

### Mitigation

- [[mitigation/reputation-scoring-fix]] - Prior reputation fix (offence_count gap)

### Tasks

- [[tasks/bug-fixes-batch-2026-08-24]] - Current session bug fix batch
- [[tasks/bug-fixes-batch-2026-08-23]] - Prior session bug fix batch
- [[tasks/bug-fixes-batch-2026-08-21]] - TEA desensitization fix batch
- [[tasks/investigation-batch-2026-08-24]] - Investigation batch
- [[tasks/tea-desensitization-fix]] - TEA desensitization fix plan
- [[tasks/task-1-reputation-scoring-fix]] - Task 1 reputation scoring
- [[tasks/expert-mode-tea-visualization-plan]] - Expert mode TEA visualization
- [[tasks/expert-pipeline-modularization]] - Expert pipeline modularization
- [[tasks/fix-expert-mode-flow-reading]] - Fix expert mode flow reading
- [[tasks/implementation-plan-fix-batch]] - Implementation plan fix batch
- [[tasks/mitigation-event-logging]] - Mitigation event logging
- [[tasks/desktop-responsive-layout]] - Desktop responsive layout
- [[tasks/light-mode-accessibility]] - Light mode accessibility
- [[tasks/professional-tone-rewrite]] - Professional tone rewrite
- [[tasks/ui-ux-overhaul]] - UI/UX overhaul
- [[tasks/expert-mode-freeze-fix-2026-08-24]] - Expert Mode freeze fix and TEA dynamic UI plan