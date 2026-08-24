---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - frontend
  - dashboard
  - expert-mode
---

# Dashboard (FastAPI)

**Directory:** `frontend/`

The web frontend for monitoring the ADDOS system.

## Framework & Architecture

- **FastAPI** + Uvicorn + Jinja2 (service running on `127.0.0.1:8080`).
- **Does not proxy backend APIs**: serves the HTML page + static assets; all data fetches go **directly from the browser to the Flask backend** (`http://127.0.0.1:5000`, CORS-enabled).

## Routes

- `GET /`: renders `dashboard.html` with injected `api_url`, poll intervals, and limits.
- `/static/*`: mounted static files (CSS, JS, vendored Chart.js).

## Dashboard UI (`dashboard.html`)

- **Header:** title, **Expert Mode toggle** (☰ Expert, beside Light Mode), theme toggle (dark/light, persisted in `localStorage`), PDF report generation modal.
- **Metric Cards:** Total Packets Analyzed, Malicious Dropped, Normal Traffic, Active Threats (with deltas).
- **Live Traffic Monitor:** Chart.js line chart with range tabs (Live / 1hr / 12hr / 24hr / Session).
- **Performance Row:** Controller CPU/mem bars, IF accuracy, RF accuracy, average response latency, false-positive rate.
- **Mitigation Audit Log:** live table populated via SSE (`/api/events`) and recent replay (`/api/recent_events`).
- **Active Mitigation & Watch List:** watchlist table with phase, attack vector, IF score, confidence, time in phase, and **Release / Blackhole buttons**.
- **IP Drawer Modal:** dynamic per-IP analysis drawer (verdict, attack description, state pills, feature signals, ML score vs threshold bars, 4-step pipeline track, **Algorithm Trace tab in Expert Mode**) triggered by clicking any table row.

### Expert Mode Panels (hidden by default, revealed by header toggle)

When **Expert Mode** is enabled (`window.EXPERT_MODE = true`, persisted in `localStorage`):

| Panel | ID | Visualization |
|---|---|---|
| **Pipeline Health** | `expert-pipeline` | Worker queue size, active workers, cache hit rate, inference latency sparkline (p50/p95/p99), flood prefilter flagged count, **Export Snapshot** button |
| **ML Internals** | `expert-ml` | IF anomaly bars (per-IP, threshold line), RF stacked class confidence bars (SYN/ICMP/UDP/Uncertain, gate line), TEA global feature variance sparklines (size variance + intensity variance, z-scores), TEA per-IP verdict pills |
| **Mitigation State Machine** | `expert-mitigation` | Phase transition diagram (Quarantine → Time Ban → Blackhole → Probation) with live IP counts, per-IP detail rows, active sinkholes with observation progress, Resource Guard tier badge |

Data sources: polls `/api/expert/live` every 2s + SSE `expert` events from `/api/events` for live TEA/IF/RF updates.

## Frontend JS Modules (`frontend/static/`)

Load order: `api → ui → chart → stats → mitigation → log → main → ip-drawer → expert` (expert.js loads last, lazy-imported on toggle).

| File | Purpose |
|---|---|
| `api.js` | Config (`API`, `POLL_MS`, `MAX_PTS`, `MAX_LOG`) + shared `apiFetch(path)` helper |
| `ui.js` | Presentation helpers, tag renderers, toasts, theme toggle, report modal, custom calendar widget |
| `chart.js` | Chart.js wrapper (`window._chart`), live push, history fetching (`/api/graph_history`) |
| `stats.js` | Polls `/api/stats`, updates metric cards, pushes chart points, polls system metrics and model info |
| `mitigation.js` | Polls `/api/quarantine_list`, DOM-diffs watchlist table, handles release/block actions |
| `log.js` | Audit log table rendering + SSE `EventSource` (`/api/events`) connection with auto-reconnect |
| `ip-drawer.js` | Self-contained per-IP threat drawer with live polling (`/api/ip_detail/<ip>/live`), **Algorithm Trace tab in Expert Mode** |
| `main.js` | Bootstrap (initial fetches, SSE connect, 2s polling intervals, row-click delegation), lazy-loads `expert.js` on Expert Mode toggle |
| `expert.js` | Expert Mode module: 4 pipeline namespaces (`ExpertState`, `ExpertStages`, `ExpertPipeline`, `ExpertMetrics`) for canvas visualization + 3 panel renderers (ML, Mitigation, TEA), polling/SSE handling, export snapshot |

## Notable Discrepancies / Notes

- `mitigation.js` header comment still refers to `quarantine.js`.
- Template polls system metrics and model info every **1000 ms** despite comments saying 5s/30s.

## Related notes

- [[backend/api]]: backend endpoints consumed by this dashboard.
- [[backend/expert-api]]: expert mode backend endpoints.
- [[config/config-and-dependencies]]: frontend config constants.

## Layout Notes

- `#expert-panels` renders as a 2-column CSS grid (ML Internals left, Mitigation State Machine right). Collapses to 1 column below 900px.
- Light mode uses a softer off-white palette (`--bg: #EDF0F7`, `--card: #FAFBFE`) to reduce eye strain compared to the previous pure-white `#F8FAFC`.
- TEA section labels: "Avg Div Entropy" (maps to `size_var`/`size_z`) and "Avg Pkt Intensity" (maps to `intensity_var`/`intensity_z`). Card title is "Global Aggregation".