"""
PrivIoT Shield — FastAPI Production Control Plane Application
Runs side-by-side with Flask without breaking changes or duplicated security engines.
"""
import time
import uuid
import logging
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app import app as flask_app
from extensions import db
from priviot.api.routers import (
    health_router, auth_router, assets_router, alerts_router,
    telemetry_router, collectors_router, containment_router,
    behavior_router, exposure_router, audit_router,
    events_router, system_router
)

logger = logging.getLogger("priviot.api")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure Flask application context is active for SQLAlchemy sessions."""
    ctx = flask_app.app_context()
    ctx.push()
    yield
    ctx.pop()

app = FastAPI(
    title="PrivIoT Shield — Security Operations API",
    description=(
        "Continuous IoT Security Operations Platform API. "
        "Provides deterministic device trust profiling, 48h behavioral baselines, "
        "evidence-backed PRI-v2 risk scoring, and 8-state firewall micro-segmentation."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# CORS configuration for modern frontend & micro-agent clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"]
)

# --------------------------------------------------------------------------
# Correlation ID & Request Latency Middleware
# --------------------------------------------------------------------------
@app.middleware("http")
async def correlation_and_audit_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id
    start_time = time.time()

    with flask_app.app_context():
        response = await call_next(request)

    duration_ms = round((time.time() - start_time) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = str(duration_ms)

    # Safe logging (Never log authorization tokens or passwords)
    logger.info(
        f"FastAPI [{request.method}] {request.url.path} -> {response.status_code} "
        f"({duration_ms}ms) [req_id={request_id}]"
    )
    return response

# --------------------------------------------------------------------------
# Consistent Standard Error Contract Handlers
# --------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = getattr(request.state, "request_id", "unknown")
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        422: "UNPROCESSABLE_ENTITY",
        500: "INTERNAL_SERVER_ERROR"
    }
    return JSONResponse(
        status_code=exc.status_code,
        headers={"X-Request-ID": req_id},
        content={
            "error": {
                "code": code_map.get(exc.status_code, "ERROR"),
                "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
                "request_id": req_id,
                "details": exc.detail if isinstance(exc.detail, dict) else {}
            }
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        headers={"X-Request-ID": req_id},
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request payload or query parameters.",
                "request_id": req_id,
                "details": {"errors": exc.errors()}
            }
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.exception(f"Unhandled exception on [{request.method}] {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        headers={"X-Request-ID": req_id},
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
                "request_id": req_id,
                "details": {}
            }
        }
    )

# --------------------------------------------------------------------------
# Mount Router Endpoints
# --------------------------------------------------------------------------
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(alerts_router)
app.include_router(telemetry_router)
app.include_router(collectors_router)
app.include_router(containment_router)
app.include_router(behavior_router)
app.include_router(exposure_router)
app.include_router(audit_router)
app.include_router(events_router)
app.include_router(system_router)
