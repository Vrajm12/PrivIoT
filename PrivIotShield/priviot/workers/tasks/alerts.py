"""
Celery Asynchronous Alert Evaluation & Notification Tasks
"""
import logging
from typing import Dict, Any
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from extensions import db
from priviot.data.models import Alert
from notification_engine import notification_engine

logger = logging.getLogger("priviot.workers.alerts")

@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def dispatch_alert_notification_task(self, alert_id: int, tenant_id: str) -> Dict[str, Any]:
    """
    Asynchronously dispatch alert notifications with deduplication cooldown.
    """
    with flask_app.app_context():
        alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
        if not alert:
            logger.error(f"Worker: Alert {alert_id} not found for tenant '{tenant_id}'")
            return {"status": "error", "error": "Alert not found in tenant context"}

        # Use notification engine with cooldown
        alert_dict = alert.to_dict()
        sent = notification_engine.dispatch_alert_notification(tenant_id, alert_dict)

        return {
            "status": "success",
            "alert_id": alert.id,
            "dispatched": sent
        }
