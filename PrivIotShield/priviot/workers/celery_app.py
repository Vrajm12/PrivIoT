"""
PrivIoT Shield — Celery 5.x Application & Worker Configuration
Coordinates asynchronous telemetry processing, behavioral profiling, and gateway containment.
"""
import os
from celery import Celery
from celery.schedules import crontab

# Environment Configuration
REDIS_URL = os.getenv("REDIS_URL", os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"))
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

# Detect testing mode
IS_TESTING = os.getenv("TESTING", "False").lower() in ("true", "1", "yes")
TASK_ALWAYS_EAGER = os.getenv("CELERY_TASK_ALWAYS_EAGER", "True" if IS_TESTING else "False").lower() in ("true", "1")

celery_app = Celery(
    "priviot_shield",
    broker=REDIS_URL if not TASK_ALWAYS_EAGER else "memory://",
    backend=RESULT_BACKEND if not TASK_ALWAYS_EAGER else "cache+memory://",
    include=[
        "priviot.workers.tasks.telemetry",
        "priviot.workers.tasks.behavior",
        "priviot.workers.tasks.alerts",
        "priviot.workers.tasks.containment",
        "priviot.workers.tasks.collectors",
        "priviot.workers.tasks.scheduler"
    ]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_always_eager=TASK_ALWAYS_EAGER,
    task_eager_propagates=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,  # Expire transient task metadata in 1 hour
    task_routes={
        "priviot.workers.tasks.telemetry.*": {"queue": "telemetry"},
        "priviot.workers.tasks.containment.*": {"queue": "containment"},
        "priviot.workers.tasks.behavior.*": {"queue": "analytics"},
        "priviot.workers.tasks.collectors.*": {"queue": "operations"},
        "priviot.workers.tasks.scheduler.*": {"queue": "scheduler"}
    },
    beat_schedule={
        "collector-fleet-health-check": {
            "task": "priviot.workers.tasks.collectors.evaluate_fleet_health_task",
            "schedule": 60.0  # Run every 60 seconds
        },
        "periodic-behavioral-baseline-sweep": {
            "task": "priviot.workers.tasks.behavior.sweep_behavioral_baselines_task",
            "schedule": 300.0  # Run every 5 minutes
        },
        "continuous-scheduled-scan-dispatch": {
            "task": "priviot.workers.tasks.scheduler.dispatch_scheduled_scans_task",
            "schedule": 60.0  # Run every 60 seconds
        }
    }
)
