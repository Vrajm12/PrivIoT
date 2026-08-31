"""
PrivIoT - Synthetic MUD Behavioral Baselining & Drift Detection Engine (Phase 2)
Establishes persistent normal communication profiles (LEARNING -> STABLE)
and generates explainable BehavioralDriftEvents when uncharacteristic destinations, ports, or protocols emerge.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

from extensions import db
from models import Asset, BehavioralBaseline, BehavioralDriftEvent, Alert

logger = logging.getLogger(__name__)


class BehavioralEngine:
    """
    Manages continuous behavioral baselines and generates evidence-backed drift findings.
    """

    def __init__(self, learning_period_hours: int = 48):
        self.learning_period_hours = learning_period_hours

    def get_or_create_baseline(self, tenant_id: str, asset: Asset, now: Optional[datetime] = None) -> BehavioralBaseline:
        """
        Retrieve or initialize a persistent Behavioral Baseline for an Asset.
        """
        now = now or datetime.utcnow()
        baseline = BehavioralBaseline.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).first()
        
        if not baseline:
            learning_end = now + timedelta(hours=self.learning_period_hours)
            baseline = BehavioralBaseline(
                tenant_id=tenant_id,
                asset_id=asset.id,
                status="LEARNING",
                allowed_destinations=json.dumps([]),
                allowed_ports=json.dumps([]),
                allowed_protocols=json.dumps([]),
                dns_whitelist=json.dumps([]),
                communication_frequency=json.dumps({"total_flows": 0, "hourly_rate": 0}),
                learning_start=now,
                learning_end=learning_end,
                last_updated=now,
                summary_json=json.dumps({"learning_progress": "0%", "known_endpoints": 0})
            )
            db.session.add(baseline)
            db.session.flush()

        return baseline

    def process_telemetry_flow(self, tenant_id: str, asset: Asset, flow_data: Dict[str, Any], 
                               now: Optional[datetime] = None, timestamp: Optional[datetime] = None) -> Optional[BehavioralDriftEvent]:
        """
        Process a normalized traffic flow observation against the asset's behavioral baseline.
        """
        now = now or timestamp or datetime.utcnow()
        baseline = self.get_or_create_baseline(tenant_id, asset, now=now)

        dst_ip = flow_data.get("dst_ip")
        dst_port = flow_data.get("dst_port")
        protocol = flow_data.get("protocol", "TCP")
        domain = flow_data.get("domain")

        allowed_dests = set(json.loads(baseline.allowed_destinations or '[]'))
        allowed_ports = set(json.loads(baseline.allowed_ports or '[]'))
        allowed_protos = set(json.loads(baseline.allowed_protocols or '[]'))
        dns_whitelist = set(json.loads(baseline.dns_whitelist or '[]'))

        # Check if baseline is in LEARNING phase
        is_learning = baseline.status == "LEARNING" and now < (baseline.learning_end or now)

        if is_learning:
            # Accumulate normal baseline patterns
            changed = False
            if dst_ip and dst_ip not in allowed_dests:
                allowed_dests.add(dst_ip)
                changed = True
            if dst_port and dst_port not in allowed_ports:
                allowed_ports.add(dst_port)
                changed = True
            if protocol and protocol not in allowed_protos:
                allowed_protos.add(protocol)
                changed = True
            if domain and domain not in dns_whitelist:
                dns_whitelist.add(domain)
                changed = True

            if changed:
                baseline.allowed_destinations = json.dumps(list(allowed_dests))
                baseline.allowed_ports = json.dumps(list(allowed_ports))
                baseline.allowed_protocols = json.dumps(list(allowed_protos))
                baseline.dns_whitelist = json.dumps(list(dns_whitelist))
                baseline.last_updated = now

            return None

        # If learning period has elapsed, promote to STABLE if currently LEARNING
        if baseline.status == "LEARNING" and now >= (baseline.learning_end or now):
            baseline.status = "STABLE"
            baseline.last_updated = now

        # Active Monitoring Phase: Evaluate Drift
        drift_type = None
        diff_desc = None
        severity = "medium"

        is_new_dst_ip = dst_ip and dst_ip not in allowed_dests and not dst_ip.startswith("192.168.") and not dst_ip.startswith("10.") and not dst_ip.startswith("127.")
        is_new_port = dst_port and dst_port not in allowed_ports and dst_port not in [53, 123] # Ignore standard gateway DNS/NTP
        is_new_domain = domain and domain not in dns_whitelist

        if is_new_dst_ip:
            drift_type = "new_destination_ip"
            diff_desc = f"New outbound connection to external IP {dst_ip}:{dst_port} ({protocol}) not present in baseline."
            severity = "high" if dst_port not in [80, 443] else "medium"
        elif is_new_port:
            drift_type = "new_destination_port"
            diff_desc = f"Communication over anomalous port {dst_port}/{protocol} not present in baseline."
            severity = "medium"
        elif is_new_domain:
            drift_type = "unclassified_dns"
            diff_desc = f"New domain resolution '{domain}' outside learned DNS profile."
            severity = "low"

        if drift_type:
            # Check for existing duplicate open drift event in last 1 hour
            recent_drift = BehavioralDriftEvent.query.filter_by(
                tenant_id=tenant_id,
                asset_id=asset.id,
                drift_type=drift_type,
                status="OPEN"
            ).first()

            if not recent_drift:
                drift_event = BehavioralDriftEvent(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    drift_type=drift_type,
                    severity=severity,
                    observed_behavior_json=json.dumps(flow_data),
                    expected_baseline_json=json.dumps({
                        "allowed_destinations_count": len(allowed_dests),
                        "allowed_ports": list(allowed_ports),
                        "allowed_protocols": list(allowed_protos)
                    }),
                    difference_description=diff_desc,
                    confidence=0.85,
                    evidence_json=json.dumps({
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "domain": domain,
                        "baseline_status": baseline.status,
                        "first_observed": now.isoformat()
                    }),
                    status="OPEN",
                    created_at=now
                )
                db.session.add(drift_event)
                baseline.status = "DRIFT_DETECTED"

                # Generate high-visibility alert
                alert = Alert(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    alert_type="behavioral_drift",
                    severity=severity,
                    title=f"Behavioral Drift Detected: {asset.vendor} {asset.device_type}",
                    description=diff_desc,
                    evidence_json=json.dumps({
                        "drift_type": drift_type,
                        "observed": flow_data,
                        "confidence": 0.85,
                        "timestamp": now.isoformat()
                    }),
                    status="OPEN",
                    created_at=now
                )
                db.session.add(alert)
                logger.warning(f"DRIFT DETECTED: Asset {asset.id} ({asset.ip_address}): {diff_desc}")
                return drift_event

        return None


# Singleton instance
behavioral_engine = BehavioralEngine()
