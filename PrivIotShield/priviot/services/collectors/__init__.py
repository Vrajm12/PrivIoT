"""
PrivIoT - Collector Fleet Lifecycle & Health Management Engine (Phase 3)
Manages enterprise sensor fleet states (PENDING, ACTIVE, DEGRADED, OFFLINE, REVOKED),
token rotation, revocation, telemetry throughput, queue health, and fleet triage dashboards.
"""

import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

from extensions import db
from models import Collector, AuditEvent

logger = logging.getLogger(__name__)


def hash_sensor_token(token: str) -> str:
    """Hash collector authentication token using SHA-256."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class CollectorManager:
    """
    Fleet controller for distributed PrivIoT sensor nodes.
    """

    def enroll_collector(self, tenant_id: str, site_id: str, name: str, 
                         collector_type: str = "passive_packet", 
                         network_scope: str = "192.168.1.0/24") -> Tuple[Collector, str]:
        """
        Enroll a new collector node in PENDING state and return a provision token.
        """
        raw_token = f"priviot_sensor_{secrets.token_urlsafe(32)}"
        token_hash = hash_sensor_token(raw_token)

        collector = Collector(
            tenant_id=tenant_id,
            site_id=site_id,
            name=name,
            collector_type=collector_type,
            network_scope=network_scope,
            auth_token_hash=token_hash,
            status="ACTIVE",
            version="3.0.0",
            last_heartbeat=datetime.utcnow(),
            capabilities_json=json.dumps(["passive_dns", "netflow_v9", "arp_snoop", "tcp_metadata"])
        )
        db.session.add(collector)
        db.session.flush()

        audit = AuditEvent(
            tenant_id=tenant_id,
            action="collector_enrolled",
            target_type="collector",
            target_id=str(collector.id),
            details_json=json.dumps({"name": name, "site_id": site_id, "network_scope": network_scope}),
            result="success"
        )
        db.session.add(audit)
        db.session.commit()
        return collector, raw_token

    def rotate_token(self, collector_id: int, tenant_id: str) -> Tuple[Collector, str]:
        """
        Rotate authentication token for a sensor node without breaking tenant operations.
        """
        collector = Collector.query.filter_by(id=collector_id, tenant_id=tenant_id).first()
        if not collector:
            raise ValueError("Collector not found")

        raw_token = f"priviot_sensor_{secrets.token_urlsafe(32)}"
        collector.auth_token_hash = hash_sensor_token(raw_token)
        collector.last_heartbeat = datetime.utcnow()

        audit = AuditEvent(
            tenant_id=tenant_id,
            action="collector_token_rotated",
            target_type="collector",
            target_id=str(collector.id),
            details_json=json.dumps({"name": collector.name, "site_id": collector.site_id}),
            result="success"
        )
        db.session.add(audit)
        db.session.commit()
        return collector, raw_token

    def revoke_collector(self, collector_id: int, tenant_id: str) -> Collector:
        """
        Revoke collector credentials and mark status as REVOKED.
        """
        collector = Collector.query.filter_by(id=collector_id, tenant_id=tenant_id).first()
        if not collector:
            raise ValueError("Collector not found")

        collector.status = "REVOKED"
        collector.auth_token_hash = f"REVOKED_{secrets.token_hex(16)}"

        audit = AuditEvent(
            tenant_id=tenant_id,
            action="collector_revoked",
            target_type="collector",
            target_id=str(collector.id),
            details_json=json.dumps({"name": collector.name, "site_id": collector.site_id}),
            result="success"
        )
        db.session.add(audit)
        db.session.commit()
        return collector

    def reactivate_collector(self, collector_id: int, tenant_id: str) -> Tuple[Collector, str]:
        """
        Reactivate a revoked or offline collector and generate a fresh token.
        """
        collector = Collector.query.filter_by(id=collector_id, tenant_id=tenant_id).first()
        if not collector:
            raise ValueError("Collector not found")

        raw_token = f"priviot_sensor_{secrets.token_urlsafe(32)}"
        collector.status = "ACTIVE"
        collector.auth_token_hash = hash_sensor_token(raw_token)
        collector.last_heartbeat = datetime.utcnow()

        audit = AuditEvent(
            tenant_id=tenant_id,
            action="collector_reactivated",
            target_type="collector",
            target_id=str(collector.id),
            details_json=json.dumps({"name": collector.name, "site_id": collector.site_id}),
            result="success"
        )
        db.session.add(audit)
        db.session.commit()
        return collector, raw_token

    def record_heartbeat(self, collector: Collector, telemetry_rate: float = 0.0, 
                         queue_depth: int = 0, errors: int = 0) -> str:
        """
        Record heartbeat and update collector state.
        """
        collector.last_heartbeat = datetime.utcnow()
        if collector.status != "REVOKED":
            if queue_depth > 1000 or errors > 10:
                collector.status = "DEGRADED"
            else:
                collector.status = "ACTIVE"
        db.session.commit()
        return collector.status

    def evaluate_fleet_health(self, tenant_id: str) -> Dict[str, Any]:
        """
        Scan all collectors for tenant, mark stale ones (>5 min) OFFLINE, and compile health summary.
        """
        now = datetime.utcnow()
        stale_threshold = now - timedelta(minutes=5)
        collectors = Collector.query.filter_by(tenant_id=tenant_id).all()

        active_count = 0
        degraded_count = 0
        offline_count = 0
        revoked_count = 0

        fleet_list = []

        for c in collectors:
            if c.status == "REVOKED":
                revoked_count += 1
            elif not c.last_heartbeat or c.last_heartbeat < stale_threshold:
                c.status = "OFFLINE"
                offline_count += 1
            elif c.status == "DEGRADED":
                degraded_count += 1
            else:
                c.status = "ACTIVE"
                active_count += 1

            fleet_list.append(c.to_dict())

        db.session.commit()

        return {
            "total_collectors": len(collectors),
            "active": active_count,
            "degraded": degraded_count,
            "offline": offline_count,
            "revoked": revoked_count,
            "health_ratio": round(active_count / max(1, len(collectors)), 2),
            "collectors": fleet_list
        }


# Singleton instance
collector_manager = CollectorManager()
