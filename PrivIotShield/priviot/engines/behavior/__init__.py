"""
PrivIoT - Radio-Level & Synthetic MUD Behavioral Baselining & Drift Engine
Processes continuous physical ESP32 telemetry (RSSI, channel, presence, encryption, flows)
with research-grade progressive maturity scoring and PRIVIOT RIM (Radio Intelligence & Movement Engine) integration.
"""

import json
import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

from extensions import db
from models import Asset, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert
from rim_engine import rim_engine

logger = logging.getLogger(__name__)


class BehavioralEngine:
    """
    Manages continuous behavioral baselines, generates evidence-backed drift findings,
    and coordinates with PRIVIOT RIM for radio fingerprinting, relative proximity, and movement trajectory.
    """

    def __init__(self, learning_period_hours: int = 48):
        self.learning_period_hours = learning_period_hours

    def calculate_maturity(self, first_seen: Optional[datetime], last_seen: Optional[datetime], 
                           obs_count: int) -> Tuple[str, str, float, str]:
        """
        Research-Grade Evidence-Based Baseline Maturity Model.
        Maps observation count and elapsed window to progressive maturity stages:
          - 0 - 10 obs:    EARLY SIGNAL        (Confidence <= 40% | LOW EVIDENCE)
          - 11 - 30 obs:   INITIAL BASELINE    (Confidence 40 - 70% | DEVELOPING)
          - 31 - 100 obs:  DEVELOPING BASELINE (Confidence 70 - 90% | STRONG)
          - 100+ obs:      STABLE BASELINE     (Confidence > 90% | HIGH)
        """
        if not first_seen or not last_seen or obs_count <= 0:
            return "EARLY SIGNAL", "LOW EVIDENCE", 0.20, "0.0 minutes"

        duration = max(0.0, (last_seen - first_seen).total_seconds())
        duration_mins = max(0.1, round(duration / 60.0, 1))

        if duration_mins < 60:
            window_str = f"{duration_mins:.1f} minutes"
        else:
            window_str = f"{duration_mins / 60.0:.1f} hours"

        if obs_count <= 10:
            stage = "EARLY SIGNAL"
            conf_band = "LOW EVIDENCE"
            confidence = min(0.40, max(0.15, obs_count * 0.04))
        elif obs_count <= 30:
            stage = "INITIAL BASELINE"
            conf_band = "DEVELOPING"
            confidence = 0.40 + ((obs_count - 10) / 20.0) * 0.30
        elif obs_count <= 100:
            stage = "DEVELOPING BASELINE"
            conf_band = "STRONG"
            confidence = 0.70 + ((obs_count - 30) / 70.0) * 0.20
        else:
            stage = "STABLE BASELINE"
            conf_band = "HIGH"
            confidence = min(0.98, 0.90 + min(0.08, (obs_count - 100) * 0.001))

        return stage, conf_band, round(confidence, 2), window_str

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
                communication_frequency=json.dumps({"total_observations": 0, "hourly_rate": 0}),
                learning_start=now,
                learning_end=learning_end,
                last_updated=now,
                summary_json=json.dumps({
                    "maturity_stage": "EARLY SIGNAL",
                    "confidence_band": "LOW EVIDENCE",
                    "maturity_confidence": 0.20,
                    "evidence_window": "0.0 minutes",
                    "observation_count": 0,
                    "profile_type": "radio_telemetry"
                })
            )
            db.session.add(baseline)
            db.session.flush()

        return baseline

    def process_radio_observation(self, tenant_id: str, asset: Asset, payload: Dict[str, Any], 
                                  now: Optional[datetime] = None) -> Optional[BehavioralDriftEvent]:
        """
        Process a real physical ESP32 Wi-Fi scan observation.
        Integrates with PRIVIOT RIM for 20-dimensional radio fingerprinting,
        multi-sample trajectory modeling, relative proximity scoring, and deduplicated drift detection.
        """
        now = now or datetime.utcnow()
        baseline = self.get_or_create_baseline(tenant_id, asset, now=now)

        rssi = payload.get("rssi")
        channel = payload.get("channel")
        ssid = payload.get("ssid") or asset.hostname or "Unknown"
        encryption_type = payload.get("encryption_type")

        # Parse current summary JSON
        summary = json.loads(baseline.summary_json or '{}')
        obs_count = summary.get("observation_count", 0) + 1

        # Calculate Progressive Maturity & Confidence
        first_seen = asset.first_seen or now
        last_seen = now
        stage, conf_band, confidence, window_str = self.calculate_maturity(first_seen, last_seen, obs_count)

        # Baseline Radio Stats Tracking
        rssi_history = summary.get("rssi_recent_history", [])
        if rssi is not None and isinstance(rssi, (int, float)):
            rssi = int(rssi)
            rssi_history.append(rssi)
            if len(rssi_history) > 60:
                rssi_history = rssi_history[-60:]

        prev_ema = summary.get("rssi_ema", float(rssi) if rssi is not None else -60.0)

        # 1. Statistical Moments via RIM Engine
        rssi_stats = rim_engine.calculate_statistical_rssi(rssi_history, rssi, prev_ema=prev_ema)
        rssi_mean = rssi_stats["mean"]
        rssi_std_dev = rssi_stats["std_dev"]
        rssi_min = rssi_stats["min"]
        rssi_max = rssi_stats["max"]
        rssi_ema = rssi_stats["ema"]

        # 2. Time-series Trajectory Window (Last K points)
        recent_points = summary.get("recent_points", [])
        if rssi is not None:
            recent_points.append({
                "timestamp": now.isoformat(),
                "rssi": rssi,
                "ema": rssi_ema,
                "channel": channel
            })
            if len(recent_points) > 15:
                recent_points = recent_points[-15:]

        # 3. Multi-Sample Trend & Movement via RIM Engine
        trajectory = rim_engine.estimate_rssi_trend_and_movement(recent_points, rssi_mean, rssi_std_dev)

        # 4. Calibrated Relative Proximity Scoring (0–100) via RIM Engine
        proximity = rim_engine.calculate_relative_proximity(rssi_ema)

        # 5. Temporal Presence & Recurrence via RIM Engine
        presence = rim_engine.evaluate_presence_and_recurrence(first_seen, last_seen, obs_count, now=now)

        # Primary Channel & Primary SSID established from physical observations
        primary_channel = summary.get("primary_channel")
        if primary_channel is None and channel:
            primary_channel = channel

        primary_ssid = summary.get("primary_ssid")
        if (primary_ssid is None or primary_ssid == "Unknown") and ssid and ssid != "Unknown" and ssid != "<hidden>":
            primary_ssid = ssid

        channel_switches = summary.get("channel_switches", 0)
        if channel and primary_channel and channel != primary_channel:
            channel_switches += 1

        ssid_changes = summary.get("ssid_changes", 0)
        if ssid and primary_ssid and ssid != primary_ssid and ssid != "Unknown":
            ssid_changes += 1

        prev_enc = summary.get("encryption_type")

        # 6. Radio Fingerprint Similarity Metric ($S \in [0.0, 1.0]$)
        fingerprint_input = {
            "channel": channel,
            "rssi": rssi,
            "encryption_type": encryption_type,
            "ssid": ssid
        }
        baseline_profile_summary = {
            "primary_channel": primary_channel,
            "primary_ssid": primary_ssid,
            "rssi_mean": rssi_mean,
            "rssi_std_dev": rssi_std_dev,
            "encryption_type": prev_enc if prev_enc is not None else encryption_type
        }
        similarity = rim_engine.calculate_fingerprint_similarity(fingerprint_input, baseline_profile_summary)

        # =====================================================================
        # INDEPENDENT MULTI-DIMENSIONAL DRIFT EVALUATION & AUTO-RECOVERY
        # =====================================================================
        active_conditions_detected = []
        new_drift_spawned = None

        # --- DIMENSION 1: Security Downgrade ---
        if encryption_type == 0 and prev_enc is not None and prev_enc > 0 and obs_count >= 5:
            active_conditions_detected.append({
                "drift_type": "security_downgrade",
                "severity": "critical",
                "is_threat": True,
                "diff_desc": f"Security Downgrade Threat: Encryption downgraded from Type {prev_enc} to Unencrypted Open Wi-Fi.",
                "expected": {"encryption_type": prev_enc}
            })
        elif encryption_type is not None and prev_enc is not None and encryption_type > 0 and encryption_type == prev_enc:
            for d in BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id, drift_type="security_downgrade", status="OPEN").all():
                d.status = "RESOLVED"
                ev = json.loads(d.evidence_json or '{}')
                ev["resolved_at"] = now.isoformat()
                ev["resolution_reason"] = f"Encryption restored to baseline Type {prev_enc}"
                d.evidence_json = json.dumps(ev)

        # --- DIMENSION 2: SSID Identity Discrepancy ---
        if ssid and primary_ssid and ssid != primary_ssid and primary_ssid != "Unknown" and obs_count >= 10:
            active_conditions_detected.append({
                "drift_type": "ssid_spoof",
                "severity": "high",
                "is_threat": True,
                "diff_desc": f"SSID Identity Anomaly: Established BSSID {asset.mac_address} modified broadcast SSID from '{primary_ssid}' to '{ssid}'.",
                "expected": {"primary_ssid": primary_ssid}
            })
        elif ssid and primary_ssid and ssid == primary_ssid:
            for d in BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id, drift_type="ssid_spoof", status="OPEN").all():
                d.status = "RESOLVED"
                ev = json.loads(d.evidence_json or '{}')
                ev["resolved_at"] = now.isoformat()
                ev["resolution_reason"] = f"SSID returned to baseline primary SSID '{primary_ssid}'"
                d.evidence_json = json.dumps(ev)

        # --- DIMENSION 3: Radio Channel Drift ---
        if channel and primary_channel and channel != primary_channel and obs_count >= 10:
            active_conditions_detected.append({
                "drift_type": "channel_drift",
                "severity": "medium",
                "is_threat": False,
                "diff_desc": f"Radio Channel Drift: Access Point shifted operation from primary Channel {primary_channel} to Channel {channel}.",
                "expected": {"primary_channel": primary_channel}
            })
        elif channel and primary_channel and channel == primary_channel:
            for d in BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id, drift_type="channel_drift", status="OPEN").all():
                d.status = "RESOLVED"
                ev = json.loads(d.evidence_json or '{}')
                ev["resolved_at"] = now.isoformat()
                ev["resolution_reason"] = f"Operating channel returned to baseline primary Channel {primary_channel}"
                d.evidence_json = json.dumps(ev)

        # --- DIMENSION 4: Statistical RSSI Anomaly (Noise-Tolerant >= 20 obs) ---
        if len(rssi_history) >= 20 and abs((rssi or -60) - rssi_mean) > max(24.0, 3.5 * rssi_std_dev):
            active_conditions_detected.append({
                "drift_type": "rssi_anomaly",
                "severity": "medium",
                "is_threat": False,
                "diff_desc": f"Signal Strength Anomaly: Observed RSSI {rssi} dBm deviates by {abs((rssi or -60) - rssi_mean):.1f} dB from baseline mean {rssi_mean:.1f} dBm (std={rssi_std_dev:.1f} dB).",
                "expected": {"rssi_baseline_mean": round(rssi_mean, 1), "rssi_std_dev": round(rssi_std_dev, 1)}
            })
        elif len(rssi_history) >= 20 and abs((rssi or -60) - rssi_mean) <= max(18.0, 2.5 * rssi_std_dev):
            for d in BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id, drift_type="rssi_anomaly", status="OPEN").all():
                d.status = "RESOLVED"
                ev = json.loads(d.evidence_json or '{}')
                ev["resolved_at"] = now.isoformat()
                ev["resolution_reason"] = f"Signal strength returned to baseline normal range ({rssi} dBm vs mean {rssi_mean:.1f} dBm)"
                d.evidence_json = json.dumps(ev)

        # =====================================================================
        # STATE-TRANSITION DEDUPLICATION FOR DETECTED CONDITIONS
        # =====================================================================
        for cond in active_conditions_detected:
            dt = cond["drift_type"]
            active_drift = BehavioralDriftEvent.query.filter_by(
                tenant_id=tenant_id,
                asset_id=asset.id,
                drift_type=dt,
                status="OPEN"
            ).first()

            if active_drift:
                active_drift.observed_behavior_json = json.dumps(payload)
                active_drift.difference_description = cond["diff_desc"]
                active_drift.confidence = confidence
                ev = json.loads(active_drift.evidence_json or '{}')
                ev["occurrence_count"] = ev.get("occurrence_count", 1) + 1
                ev["last_observed"] = now.isoformat()
                ev["confidence"] = confidence
                ev["observation_count"] = obs_count
                ev["evidence_window"] = window_str
                if dt == "channel_drift":
                    ev["current_channel"] = channel
                elif dt == "ssid_spoof":
                    ev["current_ssid"] = ssid
                active_drift.evidence_json = json.dumps(ev)
                baseline.status = "DRIFT_DETECTED"
            else:
                new_event = BehavioralDriftEvent(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    drift_type=dt,
                    severity=cond["severity"],
                    observed_behavior_json=json.dumps(payload),
                    expected_baseline_json=json.dumps(cond["expected"]),
                    difference_description=cond["diff_desc"],
                    confidence=confidence,
                    evidence_json=json.dumps({
                        "occurrence_count": 1,
                        "first_observed": now.isoformat(),
                        "last_observed": now.isoformat(),
                        "observation_count": obs_count,
                        "evidence_window": window_str,
                        "confidence_band": conf_band,
                        "current_channel": channel,
                        "current_ssid": ssid,
                        "timestamp": now.isoformat()
                    }),
                    status="OPEN",
                    created_at=now
                )
                db.session.add(new_event)
                baseline.status = "DRIFT_DETECTED"
                new_drift_spawned = new_event

                if cond["is_threat"]:
                    active_alert = Alert.query.filter_by(
                        tenant_id=tenant_id,
                        asset_id=asset.id,
                        alert_type=dt,
                        status="OPEN"
                    ).first()
                    if not active_alert:
                        alert = Alert(
                            tenant_id=tenant_id,
                            asset_id=asset.id,
                            alert_type=dt,
                            severity=cond["severity"],
                            title=f"Airspace Threat: {asset.hostname or asset.mac_address} ({dt.replace('_', ' ').title()})",
                            description=cond["diff_desc"],
                            evidence_json=json.dumps({
                                "drift_type": dt,
                                "observed": payload,
                                "confidence": confidence,
                                "timestamp": now.isoformat()
                            }),
                            status="OPEN",
                            created_at=now
                        )
                        db.session.add(alert)
                        logger.warning(f"AIRSPACE THREAT ALERT CREATED: Asset {asset.id}: {cond['diff_desc']}")

        # Check remaining open drifts to update baseline status
        remaining_open = BehavioralDriftEvent.query.filter_by(
            tenant_id=tenant_id,
            asset_id=asset.id,
            status="OPEN"
        ).count()
        if remaining_open == 0:
            baseline.status = "STABLE" if stage in ("DEVELOPING BASELINE", "STABLE BASELINE") else "LEARNING"

        # 7. Complete 20-Dimensional Radio Fingerprint Dictionary
        radio_fingerprint = {
            "bssid": asset.mac_address,
            "ssid": ssid,
            "rssi_mean": rssi_mean,
            "rssi_std_dev": rssi_std_dev,
            "rssi_min": rssi_min,
            "rssi_max": rssi_max,
            "rssi_ema": rssi_ema,
            "rssi_trend": trajectory["trend"],
            "movement_state": trajectory["movement_state"],
            "slope_db_per_sec": trajectory["slope_db_per_sec"],
            "directional_consistency": trajectory["directional_consistency"],
            "proximity_score": proximity["proximity_score"],
            "proximity_state": proximity["proximity_state"],
            "presence_state": presence["presence_state"],
            "presence_ratio": presence["presence_ratio"],
            "primary_channel": primary_channel,
            "channel_stability": round(max(0.0, min(1.0, (obs_count - channel_switches) / max(1, obs_count))), 2),
            "channel_transition_count": channel_switches,
            "observation_count": obs_count,
            "first_seen": first_seen.isoformat() if first_seen else now.isoformat(),
            "last_seen": last_seen.isoformat(),
            "encryption_type": encryption_type if encryption_type is not None else prev_enc,
            "similarity_score": similarity["similarity_score"],
            "similarity_verdict": similarity["verdict"],
            "maturity_stage": stage,
            "maturity_confidence": confidence,
            "evidence_window": window_str
        }

        # 8. Update persistent baseline summary
        updated_summary = {
            "maturity_stage": stage,
            "confidence_band": conf_band,
            "maturity_confidence": confidence,
            "evidence_window": window_str,
            "observation_count": obs_count,
            "profile_type": "radio_telemetry",
            "rssi_recent_history": rssi_history,
            "recent_points": recent_points,
            "rssi_current": rssi,
            "rssi_mean": rssi_mean,
            "rssi_min": rssi_min,
            "rssi_max": rssi_max,
            "rssi_std_dev": rssi_std_dev,
            "rssi_ema": rssi_ema,
            "proximity_score": proximity["proximity_score"],
            "proximity_zone": proximity["proximity_state"],
            "proximity_trend": trajectory["trend"],
            "movement_state": trajectory["movement_state"],
            "presence_state": presence["presence_state"],
            "presence_ratio": presence["presence_ratio"],
            "primary_channel": primary_channel,
            "channel_switches": channel_switches,
            "primary_ssid": primary_ssid,
            "ssid_changes": ssid_changes,
            "encryption_type": encryption_type if encryption_type is not None else prev_enc,
            "radio_fingerprint": radio_fingerprint,
            "similarity": similarity,
            "trajectory": trajectory,
            "activity_state": "ACTIVE_TRANSMITTING"
        }

        baseline.summary_json = json.dumps(updated_summary)
        baseline.last_updated = now
        return new_drift_spawned

    def process_telemetry_flow(self, tenant_id: str, asset: Asset, flow_data: Dict[str, Any], 
                               now: Optional[datetime] = None, timestamp: Optional[datetime] = None) -> Optional[BehavioralDriftEvent]:
        """
        Routes Wi-Fi scanner payloads to process_radio_observation or handles L3/L4 IP flows.
        """
        now = now or timestamp or datetime.utcnow()
        if flow_data.get("bssid") or flow_data.get("ssid") or flow_data.get("raw_mac") or flow_data.get("rssi") is not None:
            return self.process_radio_observation(tenant_id, asset, flow_data, now=now)

        baseline = self.get_or_create_baseline(tenant_id, asset, now=now)
        dst_ip = flow_data.get("dst_ip")
        dst_port = flow_data.get("dst_port")
        protocol = flow_data.get("protocol", "TCP")
        domain = flow_data.get("domain")

        allowed_dests = set(json.loads(baseline.allowed_destinations or '[]'))
        allowed_ports = set(json.loads(baseline.allowed_ports or '[]'))
        allowed_protos = set(json.loads(baseline.allowed_protocols or '[]'))
        dns_whitelist = set(json.loads(baseline.dns_whitelist or '[]'))

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
            baseline.allowed_protocols = json.dumps(list(allowed_protocols))
            baseline.dns_whitelist = json.dumps(list(dns_whitelist))
            baseline.last_updated = now

        return None


# Singleton instance
behavioral_engine = BehavioralEngine()
