"""
PrivIoT - Unified Production Security Pipeline (Vertical Slice)
Orchestrates:
Target Validation -> Safe Discovery -> Deterministic Fingerprinting -> Asset Reconciliation ->
Vulnerability & KEV/EPSS Matching -> PRI Risk Index -> Containment Intent & Preview -> Audit Trail.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from extensions import db
from models import Asset, AssetService, RiskAssessment, ContainmentIntent, AuditEvent, ScanJob
from safe_discovery import safe_discovery_engine, validate_target_scope
from fingerprint_pipeline import fingerprint_pipeline
from vuln_intel import vuln_engine
from exposure_engine import exposure_engine
from containment_engine import containment_engine

logger = logging.getLogger(__name__)


class SecurityPipeline:
    """
    Unified production pipeline for Continuous IoT Exposure Management & Containment.
    """

    def execute_subnet_exposure_scan(self, user_id: int, target_scope: str, tenant_id: str = "default_tenant", 
                                     profile: str = "safe", rate_limit: int = 50, concurrency: int = 10, 
                                     timeout: float = 1.0, allow_loopback: bool = False,
                                     allowed_cidrs: Optional[List[str]] = None,
                                     excluded_cidrs: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute full end-to-end vertical slice on an authorized subnet.
        """
        # 1. Validate Scope with Authorization Policy
        is_valid, err, host_ips = validate_target_scope(
            target_scope, 
            allow_loopback=allow_loopback,
            allowed_cidrs=allowed_cidrs,
            excluded_cidrs=excluded_cidrs
        )
        if not is_valid:
            raise ValueError(f"Scope validation failed: {err}")

        # 2. Initialize Scan Job in DB
        scan_job = ScanJob(
            tenant_id=tenant_id,
            user_id=user_id,
            target_scope=target_scope,
            profile=profile,
            status='running',
            rate_limit=rate_limit,
            concurrency_limit=concurrency,
            start_time=datetime.utcnow()
        )
        db.session.add(scan_job)
        db.session.commit()

        # Log audit event
        audit_start = AuditEvent(
            tenant_id=tenant_id,
            actor_id=user_id,
            action='scan_started',
            target_type='scan',
            target_id=scan_job.scan_uuid,
            details_json=json.dumps({"target_scope": target_scope, "profile": profile, "hosts_count": len(host_ips)}),
            result='success'
        )
        db.session.add(audit_start)
        db.session.commit()

        processed_assets = []

        try:
            # 3. Execute Safe Discovery
            discovery_result = safe_discovery_engine.scan_scope(
                target_scope, 
                profile=profile, 
                rate_limit=rate_limit, 
                concurrency=concurrency, 
                timeout=timeout,
                allow_loopback=allow_loopback,
                allowed_cidrs=allowed_cidrs,
                excluded_cidrs=excluded_cidrs
            )

            discovered_obs = discovery_result.get("discovered_assets", [])

            # 4. Process each discovered host
            for obs in discovered_obs:
                # 4a. Fingerprint & Reconcile Canonical Asset
                asset, is_new = fingerprint_pipeline.reconcile_asset(
                    db.session, user_id, obs, network_scope=target_scope, tenant_id=tenant_id
                )

                # 4b. Vulnerability & Threat Intelligence Lookup
                service_names = [s.service_name for s in asset.services.all()]
                open_ports = [s.port for s in asset.services.all()]
                
                device_dict = {
                    "manufacturer": asset.vendor or asset.manufacturer,
                    "model": asset.model,
                    "firmware_version": asset.firmware_version,
                    "device_type": asset.device_type,
                    "open_ports": open_ports,
                    "services": service_names
                }
                
                vuln_matches = vuln_engine.get_vulnerabilities_for_device(device_dict)

                # 4c. Compute PrivIoT Risk Index (PRI)
                pri_result = exposure_engine.calculate_pri(
                    asset_dict={"criticality": asset.criticality, "device_type": asset.device_type},
                    vulnerabilities=vuln_matches,
                    network_placement="flat_lan"
                )

                # Save Risk Assessment to DB
                risk_rec = RiskAssessment(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    risk_model_version=pri_result.get("risk_model_version", "pri-v1"),
                    threat_base=pri_result["threat_base"],
                    cisa_kev_boost=pri_result["cisa_kev_boost"],
                    epss_signal=pri_result["epss_signal"],
                    exposure_factor=pri_result["exposure_factor"],
                    criticality_weight=pri_result["criticality_weight"],
                    behavioral_penalty=pri_result["behavioral_penalty"],
                    compliance_penalty=pri_result["compliance_penalty"],
                    pri_score=pri_result["pri_score"],
                    pri_level=pri_result["pri_level"],
                    explanation_json=json.dumps(pri_result["explanation"]),
                    assessed_at=datetime.utcnow()
                )
                db.session.add(risk_rec)

                # 4d. Generate Containment Intent if High/Critical Risk
                if pri_result["pri_score"] >= 6.0:
                    intent_data = containment_engine.create_intent_for_asset(asset, pri_result)
                    
                    # Generate default pfSense policies
                    pfsense_policy = containment_engine.generate_provider_policy(intent_data, asset.ip_address, provider_name="pfsense")
                    
                    intent_rec = ContainmentIntent(
                        tenant_id=tenant_id,
                        asset_id=asset.id,
                        reason=intent_data["reason"],
                        severity=intent_data["severity"],
                        desired_effect=intent_data["desired_effect"],
                        policy_rules_json=json.dumps(intent_data.get("policy_rules", [])),
                        allowed_destinations=json.dumps(intent_data["allowed_destinations"]),
                        blocked_destinations=json.dumps(intent_data["blocked_destinations"]),
                        allowed_ports=json.dumps(intent_data["allowed_ports"]),
                        blocked_ports=json.dumps(intent_data["blocked_ports"]),
                        protocol=intent_data["protocol"],
                        status="GENERATED",
                        applied_provider="pfsense",
                        generated_policy=pfsense_policy["apply_policy"],
                        rollback_policy=pfsense_policy["rollback_policy"],
                        rollback_limitation=pfsense_policy.get("rollback_limitation")
                    )
                    db.session.add(intent_rec)

                db.session.commit()

                processed_assets.append({
                    "asset_id": asset.id,
                    "uuid": asset.uuid,
                    "ip_address": asset.ip_address,
                    "mac_address": asset.mac_address,
                    "vendor": asset.vendor,
                    "model": asset.model,
                    "device_type": asset.device_type,
                    "identity_confidence": asset.identity_confidence,
                    "vulnerabilities_count": len(vuln_matches),
                    "pri_score": pri_result["pri_score"],
                    "pri_level": pri_result["pri_level"],
                    "services": [s.to_dict() for s in asset.services.all()]
                })

            # Update Scan Job
            scan_job.status = 'completed'
            scan_job.end_time = datetime.utcnow()
            scan_job.discovered_count = len(processed_assets)
            scan_job.summary_json = json.dumps({
                "hosts_scanned": len(host_ips),
                "discovered_count": len(processed_assets),
                "high_critical_count": sum(1 for a in processed_assets if a["pri_score"] >= 6.0)
            })
            db.session.commit()

            # Log audit event
            audit_done = AuditEvent(
                actor_id=user_id,
                action='scan_completed',
                target_type='scan',
                target_id=scan_job.scan_uuid,
                details_json=json.dumps({"discovered_count": len(processed_assets), "status": "completed"}),
                result='success'
            )
            db.session.add(audit_done)
            db.session.commit()

            return {
                "scan_uuid": scan_job.scan_uuid,
                "status": "completed",
                "target_scope": target_scope,
                "profile": profile,
                "discovered_count": len(processed_assets),
                "assets": processed_assets
            }

        except Exception as e:
            logger.error(f"Scan execution failure: {str(e)}")
            scan_job.status = 'failed'
            scan_job.end_time = datetime.utcnow()
            scan_job.error_message = str(e)
            db.session.commit()
            
            audit_fail = AuditEvent(
                actor_id=user_id,
                action='scan_failed',
                target_type='scan',
                target_id=scan_job.scan_uuid,
                details_json=json.dumps({"error": str(e)}),
                result='failure'
            )
            db.session.add(audit_fail)
            db.session.commit()
            raise


# Singleton instance
security_pipeline = SecurityPipeline()
