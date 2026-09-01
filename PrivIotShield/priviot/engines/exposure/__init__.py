"""
PrivIoT - Network Exposure & PrivIoT Risk Index (PRI-v2) Engine
Calculates deterministic, fully explainable risk scores combining:
Threat Base (CVSS) + CISA KEV Boost + EPSS Signal + Exposure Scaling + Criticality Weight + Behavioral Drift Penalties + Compliance Penalties.
Supports real physical ESP32 Wi-Fi / BLE radio-layer exposure calculations.
Calculates behavioral penalties strictly from unique active drift conditions to prevent duplicate risk inflation.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from extensions import db
from models import Asset, RiskAssessment, BehavioralDriftEvent

logger = logging.getLogger(__name__)


class ExposureEngine:
    """
    Computes deterministic PrivIoT Risk Index (PRI-v2) with clear mathematical explainability.
    """

    def calculate_pri(self, asset_dict: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], 
                      network_placement: str = "flat_lan", 
                      behavioral_penalties: float = 0.0, 
                      compliance_penalties: float = 0.0) -> Dict[str, Any]:
        """
        Calculate explainable PrivIoT Risk Index (PRI-v2) for an asset.
        """
        risk_model_version = "pri-v2"

        # 1. Threat Base Calculation
        if vulnerabilities:
            threat_base = max(v.get("cvss_score", 4.0) for v in vulnerabilities)
            has_cisa_kev = any(v.get("cisa_kev", False) for v in vulnerabilities)
            max_epss = max(v.get("epss_score", 0.0) for v in vulnerabilities)
        else:
            threat_base = asset_dict.get("threat_base", 2.0)
            has_cisa_kev = False
            max_epss = 0.0

        # KEV Boost (+1.5 for actively weaponized in-the-wild exploits)
        cisa_kev_boost = 1.5 if has_cisa_kev else 0.0

        # EPSS Signal (+1.0 for >=0.90 percentile, +0.5 for >=0.50, +0.2 for >=0.10)
        if max_epss >= 0.90:
            epss_signal = 1.0
        elif max_epss >= 0.50:
            epss_signal = 0.5
        elif max_epss >= 0.10:
            epss_signal = 0.2
        else:
            epss_signal = 0.0

        # 2. Exposure Factor (Reachability Context)
        exposure_map = {
            "direct_wan": 1.0,
            "airspace_broadcast_unencrypted": 1.0,
            "airspace_wep": 0.9,
            "airspace_wpa": 0.7,
            "airspace_wpa2": 0.5,
            "airspace_wpa3": 0.4,
            "flat_lan": 0.8,
            "segmented_vlan": 0.4,
            "isolated_subnet": 0.1,
            "airspace_broadcast": 0.8
        }
        exposure_factor = exposure_map.get(network_placement.lower(), 0.8)

        # 3. Criticality Weight
        criticality = (asset_dict.get("criticality") or "tier_2").lower()
        dev_type = (asset_dict.get("device_type") or "").lower()
        
        if criticality == "tier_1" or "camera" in dev_type or "lock" in dev_type or "medical" in dev_type:
            criticality_weight = 1.2
            criticality_label = "Tier 1 (Security Critical)"
        elif criticality == "tier_3" or "tv" in dev_type or "speaker" in dev_type:
            criticality_weight = 0.8
            criticality_label = "Tier 3 (Peripheral)"
        else:
            criticality_weight = 1.0
            criticality_label = "Tier 2 (Standard Operational)"

        # 4. Mathematical Formula Calculation
        raw_threat = threat_base + cisa_kev_boost + epss_signal
        contextual_threat = raw_threat * exposure_factor * criticality_weight
        total_pri = contextual_threat + behavioral_penalties + compliance_penalties
        final_pri = min(10.0, max(0.5, round(total_pri, 1)))

        # 5. Risk Level
        if final_pri >= 8.0:
            pri_level = "critical"
        elif final_pri >= 6.0:
            pri_level = "high"
        elif final_pri >= 4.0:
            pri_level = "medium"
        else:
            pri_level = "low"

        # 6. Explainable Breakdown & Narrative
        explanation = {
            "risk_model_version": risk_model_version,
            "pri_score": final_pri,
            "pri_level": pri_level.upper(),
            "formula": "PRI = min(10.0, (Threat_Base + KEV_Boost + EPSS_Signal) * Exposure_Factor * Criticality_Weight + Behavioral_Penalties + Compliance_Penalties)",
            "components": {
                "risk_model_version": risk_model_version,
                "threat_base_cvss": threat_base,
                "cisa_kev_boost": cisa_kev_boost,
                "epss_signal": epss_signal,
                "exposure_factor": exposure_factor,
                "network_placement": network_placement,
                "criticality_weight": criticality_weight,
                "criticality_label": criticality_label,
                "behavioral_penalties": behavioral_penalties,
                "compliance_penalties": compliance_penalties
            },
            "narrative": [
                f"Base threat derived from evaluated CVSS/radio security baseline of {threat_base:.1f}.",
                f"{'Active CISA KEV weaponization detected (+1.5 boost applied).' if has_cisa_kev else 'No active CISA KEV weaponized exploits detected.'}",
                f"Network placement ({network_placement}) scales exposure risk to {exposure_factor:.1f}x.",
                f"{f'Observed active radio behavioral drift penalty: +{behavioral_penalties:.1f}.' if behavioral_penalties > 0 else 'Zero active telemetry anomalies observed.'}"
            ]
        }

        return {
            "risk_model_version": risk_model_version,
            "pri_score": final_pri,
            "pri_level": pri_level,
            "threat_base": threat_base,
            "cisa_kev_boost": cisa_kev_boost,
            "epss_signal": epss_signal,
            "exposure_factor": exposure_factor,
            "criticality_weight": criticality_weight,
            "behavioral_penalty": behavioral_penalties,
            "compliance_penalty": compliance_penalties,
            "explanation": explanation
        }

    def calculate_and_persist_radio_pri(self, tenant_id: str, asset: Asset, payload: Dict[str, Any], 
                                        now: Optional[datetime] = None) -> RiskAssessment:
        """
        Calculate and persist authentic radio-layer PRI risk for physical ESP32 Wi-Fi telemetry.
        """
        now = now or datetime.utcnow()
        encryption_type = payload.get("encryption_type")
        rssi = payload.get("rssi")
        ssid = payload.get("ssid") or asset.hostname or ""

        # Radio Encryption Threat Modeling
        compliance_penalties = 0.0
        if encryption_type == 0:  # OPEN (Unencrypted)
            threat_base = 5.5
            exposure_factor = 1.0  # Cleartext broadcast in physical airspace
            compliance_penalties = 2.0  # Violation of NIST SP 800-162 / ETSI EN 303 645
            network_placement = "airspace_broadcast_unencrypted"
        elif encryption_type == 1:  # WEP
            threat_base = 5.0
            exposure_factor = 0.9
            compliance_penalties = 1.5  # Deprecated RC4 cipher
            network_placement = "airspace_wep"
        elif encryption_type == 2:  # WPA1
            threat_base = 3.5
            exposure_factor = 0.7
            compliance_penalties = 0.5
            network_placement = "airspace_wpa"
        elif encryption_type == 5:  # WPA3
            threat_base = 1.5
            exposure_factor = 0.4
            compliance_penalties = 0.0
            network_placement = "airspace_wpa3"
        else:  # WPA2 / WPA-WPA2 (Standard)
            threat_base = 2.0
            exposure_factor = 0.5
            compliance_penalties = 0.0
            network_placement = "airspace_wpa2"

        # Hidden SSID / Rogue AP penalty
        if not ssid or ssid == "<hidden>" or ssid == "Unknown":
            compliance_penalties += 0.8

        # Immediate Proximity multiplier on unencrypted networks
        if rssi is not None and rssi >= -45 and encryption_type == 0:
            compliance_penalties += 1.0

        # Query active open drift events and evaluate by distinct drift categories (no compounding on repeats)
        open_drifts = BehavioralDriftEvent.query.filter_by(
            tenant_id=tenant_id,
            asset_id=asset.id,
            status="OPEN"
        ).all()
        distinct_drift_types = set(d.drift_type for d in open_drifts)
        behavioral_penalties = 0.0
        for dt in distinct_drift_types:
            if dt == "security_downgrade":
                behavioral_penalties += 2.0
            elif dt in ("ssid_spoof", "ssid_change"):
                behavioral_penalties += 1.5
            elif dt == "channel_drift":
                behavioral_penalties += 0.5
            elif dt == "rssi_anomaly":
                behavioral_penalties += 0.5
            else:
                behavioral_penalties += 0.5
        behavioral_penalties = min(2.5, round(behavioral_penalties, 1))

        # Asset dict
        asset_dict = {
            "vendor": asset.vendor or "Unknown",
            "model": asset.model or "Unknown Model",
            "device_type": asset.device_type or "Wireless Access Point",
            "criticality": asset.criticality or "tier_2",
            "threat_base": threat_base
        }

        # Calculate PRI
        result = self.calculate_pri(
            asset_dict=asset_dict,
            vulnerabilities=[],
            network_placement=network_placement,
            behavioral_penalties=behavioral_penalties,
            compliance_penalties=compliance_penalties
        )

        pri_score = result["pri_score"]
        pri_level = result["pri_level"]

        # Persist or update RiskAssessment record
        latest_risk = RiskAssessment.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).order_by(RiskAssessment.assessed_at.desc()).first()
        
        if not latest_risk or (now - latest_risk.assessed_at).total_seconds() > 300 or latest_risk.pri_score != pri_score:
            risk_rec = RiskAssessment(
                tenant_id=tenant_id,
                asset_id=asset.id,
                risk_model_version="pri-v2",
                threat_base=result["threat_base"],
                cisa_kev_boost=result["cisa_kev_boost"],
                epss_signal=result["epss_signal"],
                exposure_factor=result["exposure_factor"],
                criticality_weight=result["criticality_weight"],
                behavioral_penalty=result["behavioral_penalty"],
                compliance_penalty=result["compliance_penalty"],
                pri_score=pri_score,
                pri_level=pri_level,
                explanation_json=json.dumps(result["explanation"]),
                assessed_at=now
            )
            db.session.add(risk_rec)
        else:
            latest_risk.pri_score = pri_score
            latest_risk.pri_level = pri_level
            latest_risk.explanation_json = json.dumps(result["explanation"])
            latest_risk.assessed_at = now

        return result


# Singleton instance
exposure_engine = ExposureEngine()
