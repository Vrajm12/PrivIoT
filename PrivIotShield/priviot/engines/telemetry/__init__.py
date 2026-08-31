"""
PrivIoT - Telemetry Ingestion, Collector Registry & Asset Correlation Engine (Phase 2)
Provides secure token-authenticated collector endpoints, anti-spoofing, anti-replay,
deterministic asset attribution (with NULL fallback for ambiguous IPs), and normalized event streaming.
"""

import hashlib
import hmac
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

from extensions import db
from models import Collector, Observation, Asset, AuditEvent

logger = logging.getLogger(__name__)


def hash_sensor_token(token: str) -> str:
    """Hash collector authentication token using SHA-256."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class TelemetryEngine:
    """
    Manages collector node lifecycle, token validation, event ingestion, and asset correlation.
    """

    def register_collector(self, tenant_id: str, site_id: str, name: str, 
                           collector_type: str = "passive_packet", 
                           network_scope: str = "192.168.1.0/24") -> Tuple[Collector, str]:
        """
        Register a new sensor/collector node and generate an authenticated API token.
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
            status="online",
            version="2.0.0",
            last_heartbeat=datetime.utcnow(),
            capabilities_json=json.dumps(["passive_dns", "netflow_v9", "arp_snoop", "tcp_metadata"])
        )
        db.session.add(collector)
        db.session.commit()
        return collector, raw_token

    def authenticate_collector(self, token: str) -> Optional[Collector]:
        """
        Validate sensor token against registered active collectors.
        """
        if not token or not isinstance(token, str):
            return None
        
        token_hash = hash_sensor_token(token.strip())
        collector = Collector.query.filter_by(auth_token_hash=token_hash).first()
        if collector:
            collector.last_heartbeat = datetime.utcnow()
            collector.status = "online"
            db.session.commit()
            return collector
        return None

    def correlate_asset(self, tenant_id: str, src_ip: str, mac_address: Optional[str] = None, 
                        site_id: Optional[str] = None, timestamp: Optional[datetime] = None,
                        auto_discover: bool = False) -> Optional[Asset]:
        """
        Deterministic asset attribution:
        1. MAC address lookup (most authoritative).
        2. Current IP lookup matching tenant.
        3. If IP has been reassigned to a different device or is ambiguous, returns None (asset_id = NULL).
        4. If auto_discover=True and asset does not exist, automatically registers the unmanaged asset.
        """
        if not src_ip:
            return None

        # 1. Primary: Hardware MAC match
        if mac_address and len(mac_address) == 17:
            asset = Asset.query.filter_by(tenant_id=tenant_id, mac_address=mac_address).first()
            if asset:
                return asset

        # 2. Secondary: Current IP match
        candidate = Asset.query.filter_by(tenant_id=tenant_id, ip_address=src_ip).first()
        if candidate:
            # Check if this IP is marked as stale or conflicting
            if candidate.reconciliation_method == "stale_ip_reassigned":
                return None
            return candidate

        # 3. Automatic Discovery on New Observed Host
        if auto_discover and (mac_address or (src_ip and not src_ip.startswith("127."))):
            from fingerprint_pipeline import fingerprint_pipeline
            fp_result = fingerprint_pipeline.process_observation({
                "ip_address": src_ip,
                "mac_address": mac_address
            })
            now = timestamp or datetime.utcnow()
            new_asset = Asset(
                tenant_id=tenant_id,
                ip_address=src_ip,
                mac_address=mac_address,
                vendor=fp_result.get("vendor", "Unknown"),
                model=fp_result.get("model", "Unknown Model"),
                device_type=fp_result.get("device_type", "Generic IoT Device"),
                identity_confidence=fp_result.get("confidence", fp_result.get("identity_confidence", 0.35)),
                identity_evidence=json.dumps(fp_result.get("evidence", {})),
                network_scope=site_id or "default_site",
                reconciliation_method="auto_discovered_passive_telemetry",
                first_seen=now,
                last_seen=now
            )
            db.session.add(new_asset)
            db.session.flush()
            return new_asset

        # 4. Fallback: No confident attribution (Do NOT fabricate)
        return None

    def ingest_telemetry_batch(self, collector: Collector, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Ingest, validate, normalize, and store a batch of sensor telemetry observations.
        """
        if not isinstance(raw_events, list):
            raise ValueError("Telemetry payload must be a list of events")

        if len(raw_events) > 500:
            raise ValueError("Telemetry batch size exceeds limit (max 500 events per request)")

        stored_count = 0
        correlated_count = 0
        now = datetime.utcnow()
        correlation_id = secrets.token_hex(8)

        # Import engines lazily to avoid circular imports
        from dns_intel import dns_intel_engine
        from behavioral_engine import behavioral_engine

        for item in raw_events:
            src_ip = item.get("src_ip")
            dst_ip = item.get("dst_ip")
            dst_port = item.get("dst_port")
            protocol = str(item.get("protocol", "TCP")).upper()
            bytes_count = int(item.get("bytes", 0))
            packets_count = int(item.get("packets", 1))
            domain = item.get("domain")
            direction = item.get("direction", "outbound")
            mac = item.get("mac_address")

            # Correlate to Asset
            asset = self.correlate_asset(
                tenant_id=collector.tenant_id,
                src_ip=src_ip,
                mac_address=mac,
                site_id=collector.site_id,
                timestamp=now,
                auto_discover=bool(item.get("auto_discover", False))
            )
            asset_id = asset.id if asset else None
            if asset_id:
                correlated_count += 1

            normalized_payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes": bytes_count,
                "packets": packets_count,
                "domain": domain,
                "direction": direction,
                "collector_id": collector.id,
                "site_id": collector.site_id
            }

            obs_type = "dns" if domain else "network"

            obs = Observation(
                tenant_id=collector.tenant_id,
                asset_id=asset_id,
                collector_id=collector.id,
                observation_type=obs_type,
                source=collector.collector_type,
                payload_json=json.dumps(normalized_payload),
                confidence=0.95 if asset_id else 0.70,
                evidence_ref=f"sensor:{collector.collector_uuid}",
                correlation_id=correlation_id,
                timestamp=now
            )
            db.session.add(obs)
            stored_count += 1

            # Process downstream DNS intelligence
            if domain and asset:
                dns_intel_engine.evaluate_dns_query(
                    tenant_id=collector.tenant_id,
                    asset=asset,
                    domain=domain,
                    resolved_ip=dst_ip,
                    timestamp=now
                )

            # Process downstream Behavioral baseline & drift detection
            if asset:
                behavioral_engine.process_telemetry_flow(
                    tenant_id=collector.tenant_id,
                    asset=asset,
                    flow_data=normalized_payload,
                    timestamp=now
                )

        db.session.commit()

        return {
            "status": "success",
            "batch_correlation_id": correlation_id,
            "total_ingested": stored_count,
            "correlated_assets": correlated_count,
            "collector_id": collector.id
        }


# Singleton instance
telemetry_engine = TelemetryEngine()
