"""
MiniSIEM X - Intelligent Security Monitoring & Incident Response Platform
FastAPI Application Entry Point
"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import FRONTEND_DIR
from backend.database import init_db
from backend.routes.auth import router as auth_router
from backend.routes.logs import router as logs_router
from backend.routes.alerts import router as alerts_router
from backend.routes.incidents import router as incidents_router
from backend.routes.sources import router as sources_router
from backend.routes.assets import router as assets_router
from backend.routes.rules import router as rules_router
from backend.routes.reports import router as reports_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.simulation import router as simulation_router
from backend.routes.assistant import router as assistant_router
from backend.routes.threat_intel import router as threat_intel_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema, seed default rules, users, assets on startup
    init_db()
    yield

app = FastAPI(
    title="MiniSIEM X API",
    description="Intelligent Security Monitoring & Incident Response Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Safe CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(sources_router)
app.include_router(assets_router)
app.include_router(rules_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(simulation_router)
app.include_router(assistant_router)
app.include_router(threat_intel_router)

# Mount Frontend Static Assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_root():
    """Serves the main landing / portal page."""
    index_path = FRONTEND_DIR / "html" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"name": "MiniSIEM X API", "status": "Running", "docs": "/docs"}

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "platform": "MiniSIEM X", "version": "1.0.0"}

# Serve CSS files
app.mount(
    "/css",
    StaticFiles(directory=str(FRONTEND_DIR / "css")),
    name="css"
)

# Serve JavaScript files
app.mount(
    "/js",
    StaticFiles(directory=str(FRONTEND_DIR / "js")),
    name="js"
)

# Serve HTML pages
app.mount(
    "/",
    StaticFiles(directory=str(FRONTEND_DIR / "html"), html=True),
    name="pages"
)