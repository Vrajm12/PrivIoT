"""
FastAPI Router Registry
"""
from priviot.api.routers.health import router as health_router
from priviot.api.routers.auth import router as auth_router
from priviot.api.routers.assets import router as assets_router
from priviot.api.routers.alerts import router as alerts_router
from priviot.api.routers.telemetry import router as telemetry_router
from priviot.api.routers.collectors import router as collectors_router
from priviot.api.routers.containment import router as containment_router
from priviot.api.routers.behavior import router as behavior_router
from priviot.api.routers.exposure import router as exposure_router
from priviot.api.routers.audit import router as audit_router
from priviot.api.routers.events import router as events_router
from priviot.api.routers.system import router as system_router

__all__ = [
    "health_router",
    "auth_router",
    "assets_router",
    "alerts_router",
    "telemetry_router",
    "collectors_router",
    "containment_router",
    "behavior_router",
    "exposure_router",
    "audit_router",
    "events_router",
    "system_router"
]
