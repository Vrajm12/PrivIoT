"""
Celery Collector Fleet Health Sweeps
"""
import logging
from typing import Dict, Any
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from priviot.services.collectors import collector_manager

logger = logging.getLogger("priviot.workers.collectors")

@celery_app.task(name="priviot.workers.tasks.collectors.evaluate_fleet_health_task")
def evaluate_fleet_health_task() -> Dict[str, Any]:
    """
    Periodically evaluates collector heartbeat timeouts and updates offline statuses.
    """
    with flask_app.app_context():
        results = collector_manager.evaluate_fleet_health("default_tenant")
        logger.info(f"Worker: Evaluated collector fleet health: {results}")
        return {"status": "success", "fleet_health": results}
