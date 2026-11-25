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

__all__ = [
    "auth_router",
    "logs_router",
    "alerts_router",
    "incidents_router",
    "sources_router",
    "assets_router",
    "rules_router",
    "reports_router",
    "dashboard_router",
    "simulation_router",
    "assistant_router",
    "threat_intel_router"
]

