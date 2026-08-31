"""
Celery Scheduled Scan Dispatcher
"""
import logging
from typing import Dict, Any
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from priviot.services.scheduler import scheduler_engine

logger = logging.getLogger("priviot.workers.scheduler")

@celery_app.task(name="priviot.workers.tasks.scheduler.dispatch_scheduled_scans_task")
def dispatch_scheduled_scans_task() -> Dict[str, Any]:
    """
    Periodically checks active scheduled scans and enqueues due executions.
    """
    with flask_app.app_context():
        executed_count = scheduler_engine.check_and_run_schedules()
        logger.info(f"Worker: Dispatched {executed_count} scheduled discovery scans.")
        return {"status": "success", "executed_count": executed_count}
