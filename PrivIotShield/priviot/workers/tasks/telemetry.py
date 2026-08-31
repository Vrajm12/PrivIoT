"""
Celery Asynchronous Telemetry Tasks
"""
import logging
from typing import List, Dict, Any, Optional
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from extensions import db
from priviot.data.models import Collector, Observation, Asset
from priviot.engines.telemetry import telemetry_engine

logger = logging.getLogger("priviot.workers.telemetry")

@celery_app.task(bind=True, max_retries=3, default_retry_delay=5)
def process_observation_batch_task(self, tenant_id: str, collector_id: int, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Asynchronously process an ingested telemetry batch.
    """
    with flask_app.app_context():
        try:
            # 1. Verify tenant & collector boundary
            collector = Collector.query.filter_by(id=collector_id, tenant_id=tenant_id).first()
            if not collector:
                logger.error(f"Worker rejection: Collector {collector_id} not found in tenant '{tenant_id}'")
                return {"status": "error", "error": "Collector not found in tenant context"}

            # 2. Execute domain telemetry ingestion
            res = telemetry_engine.ingest_telemetry_batch(
                collector=collector,
                raw_events=raw_events
            )
            logger.info(f"Worker: Processed telemetry batch for tenant {tenant_id}: {res}")
            return res

        except ValueError as ve:
            # Non-retryable validation error
            logger.warning(f"Worker validation rejection: {ve}")
            return {"status": "validation_error", "error": str(ve)}
        except Exception as exc:
            logger.exception(f"Worker transient error in telemetry processing: {exc}")
            raise self.retry(exc=exc)
