# Route controller module providing endpoints for the primary web dashboard.
# Bridges server-side runtime configuration into the client HTML template context.
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from frontend.config import BACKEND_API, POLL_INTERVAL_MS, GRAPH_LIVE_POINTS, MAX_LOG_ROWS

router = APIRouter()


# Renders the single-page dashboard HTML shell.
# Injects configured backend API coordinates and telemetry polling thresholds into the template context.
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "api_url":  BACKEND_API,
            "poll_ms":  POLL_INTERVAL_MS,
            "max_pts":  GRAPH_LIVE_POINTS,
            "max_log":  MAX_LOG_ROWS,
        },
    )