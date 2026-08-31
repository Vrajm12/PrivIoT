"""
PrivIoT Celery Task Registry
"""
from priviot.workers.tasks.telemetry import process_observation_batch_task
from priviot.workers.tasks.behavior import sweep_behavioral_baselines_task
from priviot.workers.tasks.alerts import dispatch_alert_notification_task
from priviot.workers.tasks.containment import async_apply_containment_task
from priviot.workers.tasks.collectors import evaluate_fleet_health_task
from priviot.workers.tasks.scheduler import dispatch_scheduled_scans_task

__all__ = [
    "process_observation_batch_task",
    "sweep_behavioral_baselines_task",
    "dispatch_alert_notification_task",
    "async_apply_containment_task",
    "evaluate_fleet_health_task",
    "dispatch_scheduled_scans_task"
]
