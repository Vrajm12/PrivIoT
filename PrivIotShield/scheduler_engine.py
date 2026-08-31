"""
PrivIoT - Continuous Discovery Scheduler Engine (Phase 2)
Executes recurring scans honoring ScanAuthorizationPolicy, updates next_run schedules,
and maintains continuous attack surface visibility.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from extensions import db
from models import ScheduledScan, AuditEvent
from security_pipeline import security_pipeline

logger = logging.getLogger(__name__)


class SchedulerEngine:
    """
    Manages and triggers recurring network discovery tasks.
    """

    def create_schedule(self, user_id: int, tenant_id: str, target_scope: str, 
                        site_id: str = "default_site", profile: str = "safe", 
                        frequency: str = "daily") -> ScheduledScan:
        """
        Register a new recurring scan schedule.
        """
        now = datetime.utcnow()
        if frequency == "hourly":
            next_run = now + timedelta(hours=1)
        elif frequency == "daily":
            next_run = now + timedelta(days=1)
        else:
            next_run = now + timedelta(days=7)

        schedule = ScheduledScan(
            tenant_id=tenant_id,
            user_id=user_id,
            site_id=site_id,
            target_scope=target_scope,
            profile=profile,
            frequency=frequency,
            is_active=True,
            last_run=None,
            next_run=next_run,
            last_status="pending"
        )
        db.session.add(schedule)
        db.session.commit()
        return schedule

    def run_due_schedules(self, allow_loopback: bool = False) -> List[Dict[str, Any]]:
        """
        Execute all scheduled scans that are currently due.
        """
        now = datetime.utcnow()
        due_scans = ScheduledScan.query.filter(
            ScheduledScan.is_active == True,
            ScheduledScan.next_run <= now
        ).all()

        results = []

        for sched in due_scans:
            logger.info(f"Triggering scheduled scan on {sched.target_scope} for tenant {sched.tenant_id}")
            try:
                res = security_pipeline.execute_subnet_exposure_scan(
                    user_id=sched.user_id,
                    target_scope=sched.target_scope,
                    tenant_id=sched.tenant_id,
                    profile=sched.profile,
                    allow_loopback=allow_loopback
                )
                sched.last_run = now
                sched.last_status = "success"
                # Schedule next run
                if sched.frequency == "hourly":
                    sched.next_run = now + timedelta(hours=1)
                else:
                    sched.next_run = now + timedelta(days=1)

                results.append({"schedule_id": sched.id, "status": "success", "result": res})
            except Exception as e:
                logger.error(f"Scheduled scan failed for {sched.target_scope}: {e}")
                sched.last_status = f"failed: {str(e)}"
                sched.next_run = now + timedelta(hours=1)
                results.append({"schedule_id": sched.id, "status": "failed", "error": str(e)})

        db.session.commit()
        return results


# Singleton instance
scheduler_engine = SchedulerEngine()
