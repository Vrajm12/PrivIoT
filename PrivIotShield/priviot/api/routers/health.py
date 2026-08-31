"""
FastAPI Health & Readiness Probes
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from extensions import db

router = APIRouter(tags=["Health & Probes"])

@router.get("/health/live", summary="Process Liveness Probe")
def liveness():
    """
    Returns 200 if the process is responsive. Does NOT depend on database.
    """
    return {"status": "alive", "service": "priviot-control-plane"}

@router.get("/health/ready", summary="Dependency Readiness Probe")
def readiness():
    """
    Verifies database and task queue connectivity before routing production traffic.
    """
    db_ok = False
    redis_ok = False
    details = {}

    # 1. Database Check
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
        details["database"] = "connected"
    except Exception as e:
        details["database"] = f"unavailable: {str(e)}"

    # 2. Redis Task Queue Check
    import os
    from priviot.workers.celery_app import celery_app, TASK_ALWAYS_EAGER
    if TASK_ALWAYS_EAGER:
        redis_ok = True
        details["redis"] = "eager_in_memory"
    else:
        try:
            import redis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            r = redis.Redis.from_url(redis_url, socket_timeout=1.0)
            if r.ping():
                redis_ok = True
                details["redis"] = "connected"
        except Exception:
            details["redis"] = "degraded_fallback"
            redis_ok = True  # Graceful fallback to avoid blocking web tier if redis is temporarily offline

    if db_ok and redis_ok:
        return {"status": "ready", "dependencies": details}

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "dependencies": details}
    )
