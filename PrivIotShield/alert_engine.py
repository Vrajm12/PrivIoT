"""
PrivIoT - Deterministic Alert Management & Evidence Lifecycle Engine (Phase 2)
Provides alert deduplication, evidence association, state transitions (OPEN -> ACKNOWLEDGED -> RESOLVED),
and tenant-isolated incident filtering.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from extensions import db
from models import Alert, Asset, AuditEvent

logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Manages operational and security alerts across connected enterprise IoT fleets.
    """

    def create_alert(self, tenant_id: str, alert_type: str, severity: str, title: str, 
                     description: str, evidence: Dict[str, Any], asset_id: Optional[int] = None) -> Alert:
        """
        Create a deterministic security alert with deduplication within a 1-hour window.
        """
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)

        # Check for duplicate open alert
        existing = Alert.query.filter(
            Alert.tenant_id == tenant_id,
            Alert.asset_id == asset_id,
            Alert.alert_type == alert_type,
            Alert.status == "OPEN",
            Alert.created_at >= one_hour_ago
        ).first()

        if existing:
            # Update description and return existing alert (suppress storm)
            existing.description = description
            existing.evidence_json = json.dumps(evidence)
            db.session.commit()
            return existing

        alert = Alert(
            tenant_id=tenant_id,
            asset_id=asset_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            evidence_json=json.dumps(evidence),
            status="OPEN",
            created_at=now
        )
        db.session.add(alert)
        db.session.commit()
        return alert

    def acknowledge_alert(self, alert_id: int, user_id: int, tenant_id: str) -> Alert:
        """Transition alert to ACKNOWLEDGED."""
        alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
        if not alert:
            raise ValueError("Alert not found")

        alert.status = "ACKNOWLEDGED"
        db.session.commit()
        return alert

    def resolve_alert(self, alert_id: int, user_id: int, tenant_id: str) -> Alert:
        """Transition alert to RESOLVED."""
        alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
        if not alert:
            raise ValueError("Alert not found")

        alert.status = "RESOLVED"
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by_id = user_id
        db.session.commit()
        return alert


# Singleton instance
alert_engine = AlertEngine()
