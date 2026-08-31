"""
PrivIoT - Entitlements, Quota Enforcement & Data Retention Cleanup Engine (Phase 3)
Enforces server-side license limits (TRIAL, STARTER, BUSINESS, MSSP),
manages data lifecycle retention (7, 30, 90, 365 days), and purges expired telemetry.
"""

from datetime import datetime, timedelta
import logging
from typing import Dict, Any, Tuple

from extensions import db
from models import Observation, Asset, Collector, AuditEvent

logger = logging.getLogger(__name__)

PLAN_LIMITS = {
    "TRIAL": {
        "max_assets": 25,
        "max_collectors": 1,
        "max_sites": 1,
        "telemetry_retention_days": 7,
        "containment_enabled": False,
        "mssp_dashboard": False
    },
    "STARTER": {
        "max_assets": 250,
        "max_collectors": 3,
        "max_sites": 2,
        "telemetry_retention_days": 30,
        "containment_enabled": True,
        "mssp_dashboard": False
    },
    "BUSINESS": {
        "max_assets": 2500,
        "max_collectors": 15,
        "max_sites": 10,
        "telemetry_retention_days": 90,
        "containment_enabled": True,
        "mssp_dashboard": False
    },
    "MSSP": {
        "max_assets": 100000,
        "max_collectors": 500,
        "max_sites": 200,
        "telemetry_retention_days": 365,
        "containment_enabled": True,
        "mssp_dashboard": True
    }
}


class EntitlementsEngine:
    """
    Server-side license verification and quota management.
    """

    def __init__(self):
        # Tenant plan cache: {tenant_id: "BUSINESS"}
        self.tenant_plans: Dict[str, str] = {}

    def get_tenant_plan(self, tenant_id: str) -> str:
        return self.tenant_plans.get(tenant_id, "BUSINESS")

    def set_tenant_plan(self, tenant_id: str, plan_name: str):
        if plan_name.upper() not in PLAN_LIMITS:
            raise ValueError(f"Invalid plan name: {plan_name}")
        self.tenant_plans[tenant_id] = plan_name.upper()

    def check_asset_quota(self, tenant_id: str) -> Tuple[bool, str]:
        plan = self.get_tenant_plan(tenant_id)
        limits = PLAN_LIMITS[plan]
        current_assets = Asset.query.filter_by(tenant_id=tenant_id).count()

        if current_assets >= limits["max_assets"]:
            return False, f"Asset quota exceeded for plan '{plan}' ({current_assets}/{limits['max_assets']})"
        return True, "Within quota"

    def check_collector_quota(self, tenant_id: str) -> Tuple[bool, str]:
        plan = self.get_tenant_plan(tenant_id)
        limits = PLAN_LIMITS[plan]
        current_collectors = Collector.query.filter_by(tenant_id=tenant_id).count()

        if current_collectors >= limits["max_collectors"]:
            return False, f"Collector quota exceeded for plan '{plan}' ({current_collectors}/{limits['max_collectors']})"
        return True, "Within quota"

    def is_containment_allowed(self, tenant_id: str) -> bool:
        plan = self.get_tenant_plan(tenant_id)
        return PLAN_LIMITS[plan]["containment_enabled"]

    def is_mssp_allowed(self, tenant_id: str) -> bool:
        plan = self.get_tenant_plan(tenant_id)
        return PLAN_LIMITS[plan]["mssp_dashboard"]

    def purge_expired_telemetry(self, tenant_id: str) -> int:
        """
        Purge raw observations older than tenant's plan retention window.
        Does NOT touch active assets or security evidence.
        """
        plan = self.get_tenant_plan(tenant_id)
        retention_days = PLAN_LIMITS[plan]["telemetry_retention_days"]
        cutoff = datetime.utcnow() - timedelta(days=retention_days)

        expired_query = Observation.query.filter(
            Observation.tenant_id == tenant_id,
            Observation.timestamp < cutoff
        )
        count = expired_query.count()
        if count > 0:
            expired_query.delete(synchronize_session=False)
            audit = AuditEvent(
                tenant_id=tenant_id,
                action="retention_purge_executed",
                target_type="observation",
                target_id="bulk",
                details_json=f'{{"purged_events": {count}, "retention_days": {retention_days}}}',
                result="success"
            )
            db.session.add(audit)
            db.session.commit()
            logger.info(f"Purged {count} expired telemetry observations for tenant {tenant_id}")
        return count


# Singleton instance
entitlements_engine = EntitlementsEngine()
