# Application factory configuring FastAPI routing, template engines, and static mounts.
# Provides the ASGI service instance powering the operator dashboard interface.
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from frontend.routes.dashboard import router as dashboard_router

BASE_DIR = Path(__file__).parent


# Instantiates and configures the FastAPI web application.
# Mounts static asset directories, registers Jinja2 templates, and attaches dashboard route handlers.
def create_app() -> FastAPI:
    app = FastAPI(title="A-DDoS Dashboard", docs_url=None, redoc_url=None)

    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    app.state.templates = Jinja2Templates(directory=BASE_DIR / "templates")
    app.include_router(dashboard_router)

    return app