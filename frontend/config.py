# Central configuration constants defining backend service endpoints and client runtime limits.
# Centralizes connection targets and UI parameters for consistent dashboard operation.

# Network coordinates for connecting to the detection backend and binding the local dashboard server.
BACKEND_API = "http://127.0.0.1:5000"
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8080

# Client-side time-series buffer capacity, telemetry polling intervals, and log retention thresholds.
GRAPH_LIVE_POINTS = 30
POLL_INTERVAL_MS = 2000
MAX_LOG_ROWS = 0
