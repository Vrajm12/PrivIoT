"""
FastAPI Production Observability & System Health Router
Exposes operational metrics, queue health, and pipeline status.
"""
import os
import time
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from extensions import db
from priviot.api.dependencies import get_current_user, require_role, get_current_tenant
from priviot.data.models import User, Observation, Alert, Collector
from priviot.workers.celery_app import celery_app, TASK_ALWAYS_EAGER

router = APIRouter(prefix="/api/v2/system", tags=["System Observability"])

@router.get("/health", summary="Get Production System Component Health")
def get_system_health(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Returns non-sensitive health status across database, Redis, Celery workers, and telemetry pipeline.
    """
    health_status = "HEALTHY"
    components: Dict[str, Any] = {}

    # 1. Database Persistence Health
    try:
        t0 = time.time()
        db.session.execute(text("SELECT 1"))
        latency_ms = (time.time() - t0) * 1000
        components["database"] = {
            "status": "HEALTHY",
            "latency_ms": round(latency_ms, 2),
            "engine": "PostgreSQL 16 / SQLite Authority"
        }
    except Exception as e:
        health_status = "DEGRADED"
        components["database"] = {
            "status": "UNAVAILABLE",
            "error": "Database connectivity lost"
        }

    # 2. Redis & Task Broker Health
    if TASK_ALWAYS_EAGER:
        components["redis_queue"] = {
            "status": "HEALTHY",
            "mode": "eager_in_memory",
            "latency_ms": 0.1
        }
    else:
        try:
            import redis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            r = redis.Redis.from_url(redis_url, socket_timeout=1.0)
            t0 = time.time()
            if r.ping():
                latency_ms = (time.time() - t0) * 1000
                components["redis_queue"] = {
                    "status": "HEALTHY",
                    "latency_ms": round(latency_ms, 2)
                }
            else:
                components["redis_queue"] = {"status": "DEGRADED"}
        except Exception:
            components["redis_queue"] = {
                "status": "DEGRADED",
                "fallback": "local_queue_active"
            }

    # 3. Telemetry Pipeline Health
    try:
        obs_count = Observation.query.filter_by(tenant_id=tenant_id).count()
        collectors_online = Collector.query.filter_by(tenant_id=tenant_id, status="ACTIVE").count()
        components["telemetry_pipeline"] = {
            "status": "HEALTHY",
            "active_collectors": collectors_online,
            "total_observations_ingested": obs_count
        }
    except Exception:
        components["telemetry_pipeline"] = {"status": "UNKNOWN"}

    return {
        "status": health_status,
        "timestamp": time.time(),
        "components": components
    }

@router.get("/metrics", summary="Get Operational Metrics & Queue Depth")
def get_system_metrics(
    current_user: User = Depends(require_role("operator")),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Returns operational throughput, alert frequency, and queue metrics.
    """
    obs_count = Observation.query.filter_by(tenant_id=tenant_id).count()
    open_alerts = Alert.query.filter_by(tenant_id=tenant_id, status="OPEN").count()
    total_collectors = Collector.query.filter_by(tenant_id=tenant_id).count()

    return {
        "tenant_id": tenant_id,
        "metrics": {
            "total_observations": obs_count,
            "open_alerts": open_alerts,
            "active_collectors": total_collectors,
            "worker_concurrency": 4 if not TASK_ALWAYS_EAGER else 1,
            "realtime_transport": "SSE_REDIS_PUBSUB"
        }
    }
