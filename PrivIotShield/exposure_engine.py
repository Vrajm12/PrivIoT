"""
PrivIoT - Network Exposure & PrivIoT Risk Index (PRI-v2) Engine
Calculates deterministic, fully explainable risk scores combining:
Threat Base (CVSS) + CISA KEV Boost + EPSS Signal + Exposure Scaling + Criticality Weight + Behavioral Drift Penalties + Compliance Penalties.
"""

import json
import logging
from typing import Dict, List, Any, Optional

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
        
        Args:
            asset_dict: Asset attributes (vendor, model, device_type, criticality)
            vulnerabilities: List of matched CVE/vulnerability records
            network_placement: "direct_wan", "flat_lan", "segmented_vlan", "isolated_subnet"
            behavioral_penalties: Additive penalty for observed data exfiltration / cleartext leaks / behavioral drift
            compliance_penalties: Additive penalty for ETSI/NIST failure or EOL status
        """
        risk_model_version = "pri-v2"

        # 1. Threat Base Calculation
        if vulnerabilities:
            threat_base = max(v.get("cvss_score", 4.0) for v in vulnerabilities)
            has_cisa_kev = any(v.get("cisa_kev", False) for v in vulnerabilities)
            max_epss = max(v.get("epss_score", 0.0) for v in vulnerabilities)
        else:
            threat_base = 2.0
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
            "flat_lan": 0.8,
            "segmented_vlan": 0.4,
            "isolated_subnet": 0.1
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
                f"Base threat derived from maximum CVSS v3.1 score of {threat_base:.1f}.",
                f"{'Active CISA KEV weaponization detected (+1.5 boost applied).' if has_cisa_kev else 'No active CISA KEV weaponized exploits detected.'}",
                f"EPSS likelihood score is {max_epss:.3f} (+{epss_signal:.1f} signal).",
                f"Network placement ({network_placement}) scales exposure risk to {exposure_factor:.1f}x.",
                f"Asset criticality evaluated as {criticality_label} ({criticality_weight:.1f}x multiplier).",
                f"{f'Observed telemetry behavioral drift / exfiltration penalty: +{behavioral_penalties:.1f}.' if behavioral_penalties > 0 else 'Zero active telemetry anomalies observed.'}"
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


# Singleton instance
exposure_engine = ExposureEngine()
