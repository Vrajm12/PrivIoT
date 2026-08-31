"""
Celery Asynchronous Behavioral Profiling Tasks
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Any
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from extensions import db
from priviot.data.models import BehavioralBaseline, Asset

logger = logging.getLogger("priviot.workers.behavior")

@celery_app.task(name="priviot.workers.tasks.behavior.sweep_behavioral_baselines_task")
def sweep_behavioral_baselines_task() -> Dict[str, Any]:
    """
    Periodically sweeps learning baselines and transitions assets past the 48-hour window to STABLE.
    """
    with flask_app.app_context():
        threshold = datetime.utcnow() - timedelta(hours=48)
        learning_baselines = BehavioralBaseline.query.filter(
            BehavioralBaseline.status == 'LEARNING',
            BehavioralBaseline.learning_start <= threshold
        ).all()

        promoted_count = 0
        for b in learning_baselines:
            b.status = 'STABLE'
            b.learning_end = datetime.utcnow()
            promoted_count += 1

        if promoted_count > 0:
            db.session.commit()
            logger.info(f"Worker: Promoted {promoted_count} baselines to STABLE state.")

        return {"status": "success", "promoted_count": promoted_count}
