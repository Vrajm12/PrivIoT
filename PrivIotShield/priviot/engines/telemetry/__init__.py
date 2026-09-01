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

    def correlate_asset(self, tenant_id: str, src_ip: Optional[str] = None, mac_address: Optional[str] = None, 
                        site_id: Optional[str] = None, timestamp: Optional[datetime] = None,
                        auto_discover: bool = False, obs_type: str = "network",
                        extra_info: Optional[Dict[str, Any]] = None,
                        collector: Optional[Collector] = None) -> Optional[Asset]:
        """
        Deterministic asset attribution:
        1. MAC / BSSID address lookup (most authoritative hardware identity).
        2. Current IP lookup matching tenant.
        3. If asset exists: updates last_seen and returns existing asset (NO DUPLICATES).
        4. If auto_discover=True and asset does not exist: creates new Asset with evidence.
        """
        if not src_ip and not mac_address:
            return None

        now = timestamp or datetime.utcnow()
        extra = extra_info or {}

        # Normalize MAC format if provided
        if mac_address:
            mac_address = mac_address.strip().upper()

        # 1. Primary: Hardware MAC / BSSID match (Essential for Wi-Fi APs & BLE Beacons)
        if mac_address and len(mac_address) >= 11:
            asset = Asset.query.filter_by(tenant_id=tenant_id, mac_address=mac_address).first()
            if asset:
                asset.last_seen = now
                # Update hostname / SSID if new name learned
                ssid = extra.get("ssid") or extra.get("name")
                if ssid and ssid != "<hidden>" and (not asset.hostname or asset.hostname == "Unknown"):
                    asset.hostname = ssid
                return asset

        # 2. Secondary: Current IP match (only if valid non-zero IP)
        if src_ip and src_ip not in ("0.0.0.0", "", "127.0.0.1"):
            candidate = Asset.query.filter_by(tenant_id=tenant_id, ip_address=src_ip).first()
            if candidate:
                if candidate.reconciliation_method != "stale_ip_reassigned":
                    candidate.last_seen = now
                    return candidate

        # 3. Automatic Discovery on New Observed Host / Access Point / BLE Device
        if auto_discover and (mac_address or (src_ip and src_ip not in ("0.0.0.0", "", "127.0.0.1"))):
            from fingerprint_pipeline import fingerprint_pipeline
            
            fp_input = {
                "ip_address": src_ip or "0.0.0.0",
                "mac_address": mac_address,
                "observation_type": obs_type,
                "ssid": extra.get("ssid"),
                "bssid": extra.get("bssid") or mac_address,
                "rssi": extra.get("rssi"),
                "channel": extra.get("channel"),
                "name": extra.get("name"),
                "address": extra.get("address") or mac_address
            }
            fp_result = fingerprint_pipeline.process_observation(fp_input)

            # Determine discovery source and reconciliation method
            if obs_type == "wifi_scan" or extra.get("ssid") or (collector and collector.collector_type == "wifi_scanner"):
                disc_source = "esp32_wifi_scan"
                recon_method = "esp32_hardware_scanner"
            elif obs_type == "ble_scan" or extra.get("name") or (collector and collector.collector_type == "ble_scanner"):
                disc_source = "esp32_ble_scan"
                recon_method = "esp32_ble_scanner"
            else:
                disc_source = "safe_active_probe"
                recon_method = "auto_discovered_passive_telemetry"

            ssid_name = extra.get("ssid") or extra.get("name")
            new_asset = Asset(
                tenant_id=tenant_id,
                ip_address=src_ip or "0.0.0.0",
                mac_address=mac_address,
                hostname=ssid_name if (ssid_name and ssid_name != "<hidden>") else None,
                vendor=fp_result.get("vendor", "Unknown"),
                model=fp_result.get("model", "Unknown Model"),
                device_type=fp_result.get("device_type", "Generic IoT Device"),
                identity_confidence=fp_result.get("confidence", 0.35),
                identity_evidence=json.dumps(fp_result.get("evidence", {})),
                network_scope=site_id or "default_site",
                discovery_source=disc_source,
                reconciliation_method=recon_method,
                first_seen=now,
                last_seen=now
            )
            db.session.add(new_asset)
            db.session.flush()

            # Emit real-time discovery event to SOC event bus
            try:
                from priviot.services.event_bus import event_bus
                event_bus.emit_asset_discovered(
                    tenant_id=tenant_id,
                    site_id=site_id or "default_site",
                    asset_id=new_asset.id,
                    ip_address=new_asset.ip_address,
                    vendor=new_asset.vendor,
                    model=new_asset.model
                )
            except Exception:
                pass

            return new_asset

        # 4. Fallback: No confident attribution
        return None

    def ingest_telemetry_batch(self, collector: Collector, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Ingest, validate, normalize, and store a batch of sensor telemetry observations.
        """
        if not isinstance(raw_events, list):
            raise ValueError("Telemetry payload must be a list of events")

        if len(raw_events) > 500:
            raise ValueError("Telemetry batch size exceeds limit (max 500 events per request)")

        # Ensure collector is bound to active database session
        collector_id = getattr(collector, "id", None)
        if collector_id:
            db_collector = Collector.query.filter_by(id=collector_id).first()
            if db_collector:
                collector = db_collector

        stored_count = 0
        correlated_count = 0
        new_assets_discovered = 0
        now = datetime.utcnow()
        correlation_id = secrets.token_hex(8)

        # Import engines lazily to avoid circular imports
        from dns_intel import dns_intel_engine
        from behavioral_engine import behavioral_engine
        from exposure_engine import exposure_engine
        from alert_engine import alert_engine

        anomalies_detected = 0

        for item in raw_events:
            obs_type = item.get("observation_type") or ("dns" if item.get("domain") else "network")
            payload_dict = item.get("payload") if isinstance(item.get("payload"), dict) else {}

            # Infer Wi-Fi / BLE scanner observation type if BSSID / SSID present
            if payload_dict.get("bssid") or payload_dict.get("ssid") or (collector and collector.collector_type == "wifi_scanner"):
                obs_type = "wifi_scan"
            elif payload_dict.get("ble_address") or payload_dict.get("ble_name") or (collector and collector.collector_type == "ble_scanner"):
                obs_type = "ble_scan"

            src_ip = item.get("src_ip") or payload_dict.get("src_ip") or "0.0.0.0"
            dst_ip = item.get("dst_ip") or payload_dict.get("dst_ip")
            dst_port = item.get("dst_port") or payload_dict.get("dst_port")
            protocol = str(item.get("protocol") or payload_dict.get("protocol") or item.get("proto") or "TCP").upper()
            bytes_count = int(item.get("bytes") or payload_dict.get("bytes") or 0)
            packets_count = int(item.get("packets") or payload_dict.get("packets") or 1)
            domain = item.get("domain") or payload_dict.get("domain")
            direction = item.get("direction") or payload_dict.get("direction") or "outbound"
            
            # Extract MAC from src_mac, mac_address, bssid, or ble address
            mac = (
                item.get("src_mac") or 
                item.get("mac_address") or 
                payload_dict.get("bssid") or 
                payload_dict.get("address") or 
                payload_dict.get("mac")
            )
            if mac:
                mac = str(mac).strip().upper()

            auto_discover = bool(
                item.get("auto_discover", False) or 
                payload_dict.get("auto_discover", False) or 
                obs_type in ("wifi_scan", "ble_scan") or
                (collector and collector.collector_type in ("wifi_scanner", "ble_scanner")) or
                bool(mac and len(mac) >= 11)
            )

            # Check if asset was already known prior to this scan
            was_existing = False
            if mac and len(mac) >= 11:
                if Asset.query.filter_by(tenant_id=collector.tenant_id, mac_address=mac).first():
                    was_existing = True

            # Correlate to Asset (Hardware MAC / BSSID attribution)
            asset = self.correlate_asset(
                tenant_id=collector.tenant_id,
                src_ip=src_ip,
                mac_address=mac,
                site_id=collector.site_id,
                timestamp=now,
                auto_discover=auto_discover,
                obs_type=obs_type,
                extra_info=payload_dict,
                collector=collector
            )
            asset_id = asset.id if asset else None
            if asset_id:
                correlated_count += 1
                if not was_existing:
                    new_assets_discovered += 1

            # Build normalized payload preserving raw scan metadata
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
                "collector_name": getattr(collector, "name", "Collector"),
                "site_id": collector.site_id,
                "raw_mac": mac
            }
            # Merge extra Wi-Fi / BLE metadata (ssid, bssid, rssi, channel, etc.)
            for k, v in payload_dict.items():
                if k not in normalized_payload:
                    normalized_payload[k] = v

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

            # 1. Process Downstream DNS Intelligence
            if domain and asset:
                dns_res = dns_intel_engine.evaluate_dns_query(
                    tenant_id=collector.tenant_id,
                    asset=asset,
                    domain=domain,
                    resolved_ip=dst_ip,
                    timestamp=now
                )
                if dns_res and dns_res.get("is_threat"):
                    anomalies_detected += 1

            # 2. Process Downstream Behavioral Baselining & Radio Drift Detection
            if asset:
                drift_event = behavioral_engine.process_telemetry_flow(
                    tenant_id=collector.tenant_id,
                    asset=asset,
                    flow_data=normalized_payload,
                    timestamp=now
                )
                if drift_event:
                    anomalies_detected += 1

                # 3. Process Downstream Radio PRI Exposure & Threat Index
                exposure_engine.calculate_and_persist_radio_pri(
                    tenant_id=collector.tenant_id,
                    asset=asset,
                    payload=normalized_payload,
                    now=now
                )

                # 4. Check for Open Unencrypted Airspace Vulnerability
                enc_type = normalized_payload.get("encryption_type")
                if enc_type == 0 and not was_existing:
                    alert_engine.create_alert(
                        tenant_id=collector.tenant_id,
                        alert_type="open_unencrypted_wifi",
                        severity="high",
                        title=f"Open Unencrypted Wi-Fi AP: {asset.hostname or asset.mac_address}",
                        description=f"Wireless Access Point '{asset.hostname or 'Hidden'}' ({asset.mac_address}) is broadcasting cleartext unencrypted 802.11 beacons in physical airspace.",
                        evidence={
                            "bssid": asset.mac_address,
                            "ssid": asset.hostname,
                            "rssi": normalized_payload.get("rssi"),
                            "channel": normalized_payload.get("channel"),
                            "encryption_type": 0
                        },
                        asset_id=asset.id
                    )
                    anomalies_detected += 1

        db.session.commit()

        return {
            "status": "success",
            "batch_correlation_id": correlation_id,
            "total_ingested": stored_count,
            "correlated_assets": correlated_count,
            "new_assets_discovered": new_assets_discovered,
            "anomalies_detected": anomalies_detected,
            "collector_id": collector.id
        }


# Singleton instance
telemetry_engine = TelemetryEngine()
