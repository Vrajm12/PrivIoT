"""
PrivIoT - Multi-Site Operations & MSSP Multi-Tenant Fleet Aggregator (Phase 3)
Enforces hierarchical management: MSSP -> Customer Tenant -> Site -> Network -> Collector -> Asset.
Provides multi-site risk triage, customer posture ranking, and strictly prevents cross-tenant data leaks.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from extensions import db
from models import Asset, Collector, Alert, BehavioralDriftEvent, RiskAssessment, AuditEvent

logger = logging.getLogger(__name__)


class MSSPManager:
    """
    Manages multi-site and multi-tenant MSSP operational visibility and triage.
    """

    def get_site_posture(self, tenant_id: str, site_id: str) -> Dict[str, Any]:
        """
        Compile operational security posture for a specific enterprise site.
        """
        assets = Asset.query.filter_by(tenant_id=tenant_id, network_scope=site_id).all()
        if not assets:
            # Fallback search by site_id in network_scope string
            assets = Asset.query.filter(Asset.tenant_id == tenant_id).all()

        collectors = Collector.query.filter_by(tenant_id=tenant_id, site_id=site_id).all()
        open_alerts = Alert.query.filter_by(tenant_id=tenant_id, status='OPEN').count()
        drifts = BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, status='OPEN').count()

        total_assets = len(assets)
        critical_assets = sum(1 for a in assets if a.get_latest_risk() and a.get_latest_risk().pri_level == 'critical')
        high_assets = sum(1 for a in assets if a.get_latest_risk() and a.get_latest_risk().pri_level == 'high')

        avg_pri = 0.0
        if total_assets > 0:
            scores = [a.get_latest_risk().pri_score for a in assets if a.get_latest_risk()]
            avg_pri = round(sum(scores) / max(1, len(scores)), 1) if scores else 3.0

        return {
            "tenant_id": tenant_id,
            "site_id": site_id,
            "total_assets": total_assets,
            "critical_assets": critical_assets,
            "high_assets": high_assets,
            "average_pri": avg_pri,
            "open_alerts": open_alerts,
            "active_drifts": drifts,
            "collectors_count": len(collectors),
            "offline_collectors": sum(1 for c in collectors if c.status == 'OFFLINE')
        }

    def get_mssp_triage_dashboard(self, tenant_ids: List[str]) -> Dict[str, Any]:
        """
        Aggregate multi-tenant triage dashboard across authorized customer accounts.
        """
        customer_rankings = []
        aggregate_assets = 0
        aggregate_critical = 0
        aggregate_alerts = 0
        aggregate_offline_sensors = 0

        for tid in tenant_ids:
            assets = Asset.query.filter_by(tenant_id=tid).all()
            collectors = Collector.query.filter_by(tenant_id=tid).all()
            alerts = Alert.query.filter_by(tenant_id=tid, status='OPEN').all()
            drifts = BehavioralDriftEvent.query.filter_by(tenant_id=tid, status='OPEN').all()

            crit_count = sum(1 for a in assets if a.get_latest_risk() and a.get_latest_risk().pri_level == 'critical')
            offline_count = sum(1 for c in collectors if c.status == 'OFFLINE')

            aggregate_assets += len(assets)
            aggregate_critical += crit_count
            aggregate_alerts += len(alerts)
            aggregate_offline_sensors += offline_count

            scores = [a.get_latest_risk().pri_score for a in assets if a.get_latest_risk()]
            avg_pri = round(sum(scores) / max(1, len(scores)), 1) if scores else 2.5

            customer_rankings.append({
                "tenant_id": tid,
                "total_assets": len(assets),
                "critical_assets": crit_count,
                "average_pri": avg_pri,
                "open_alerts": len(alerts),
                "active_drifts": len(drifts),
                "offline_collectors": offline_count,
                "triage_priority": "CRITICAL" if crit_count > 0 or offline_count > 0 else "NORMAL"
            })

        # Rank customers by risk priority
        customer_rankings.sort(key=lambda x: (x["critical_assets"], x["average_pri"]), reverse=True)

        return {
            "total_customers": len(tenant_ids),
            "aggregate_assets": aggregate_assets,
            "aggregate_critical_assets": aggregate_critical,
            "aggregate_open_alerts": aggregate_alerts,
            "aggregate_offline_sensors": aggregate_offline_sensors,
            "customer_rankings": customer_rankings
        }


# Singleton instance
mssp_manager = MSSPManager()
