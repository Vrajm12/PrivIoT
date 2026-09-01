"""
FastAPI Behavioral Baselines & Drift Feed Router
Provides real radio-level behavioural telemetry statistics and drift events.
"""
from typing import Optional, List, Dict, Any
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from app import app as flask_app
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, Asset, Observation, BehavioralBaseline, BehavioralDriftEvent
from priviot.api.schemas.behavior import (
    BehavioralBaselineResponse, BehavioralDriftResponse, DriftFeedResponse
)

router = APIRouter(prefix="/api/v2/behavior", tags=["Behavioral Profiling & Drift"])

@router.get("/stats", summary="Get Fleet Behavioral Baselining Statistics")
def get_behavioral_stats(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Returns authentic fleet-wide telemetry statistics, observation density, and evidence maturity distribution.
    """
    with flask_app.app_context():
        total_obs = Observation.query.filter_by(tenant_id=tenant_id).count()
        assets = Asset.query.filter_by(tenant_id=tenant_id).all()
        baselines = BehavioralBaseline.query.filter_by(tenant_id=tenant_id).all()
        open_drifts = BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, status="OPEN").count()

        earliest_obs = Observation.query.filter_by(tenant_id=tenant_id).order_by(Observation.timestamp.asc()).first()
        latest_obs = Observation.query.filter_by(tenant_id=tenant_id).order_by(Observation.timestamp.desc()).first()

        window_mins = 0.0
        if earliest_obs and latest_obs and earliest_obs.timestamp and latest_obs.timestamp:
            window_mins = max(0.1, round((latest_obs.timestamp - earliest_obs.timestamp).total_seconds() / 60.0, 1))

        if window_mins < 60:
            window_str = f"{window_mins:.1f} minutes"
        else:
            window_str = f"{window_mins / 60.0:.1f} hours"

        maturity_dist = {"PRELIMINARY": 0, "DEVELOPING": 0, "ESTABLISHED": 0, "MATURE": 0}
        for b in baselines:
            summary = json.loads(b.summary_json or '{}')
            stage = summary.get("maturity_stage", "PRELIMINARY")
            maturity_dist[stage] = maturity_dist.get(stage, 0) + 1

        if not baselines and assets:
            maturity_dist["PRELIMINARY"] = len(assets)

        return {
            "total_real_observations": total_obs,
            "total_assets_monitored": len(assets),
            "observation_window_minutes": window_mins,
            "observation_window_formatted": window_str,
            "earliest_observation": earliest_obs.timestamp.isoformat() if earliest_obs else None,
            "latest_observation": latest_obs.timestamp.isoformat() if latest_obs else None,
            "maturity_distribution": maturity_dist,
            "open_drifts_count": open_drifts,
            "profile_type": "ESP32 Physical 2.4GHz Airspace Scanner",
            "safe_flows_status": "NTP / Gateway Airspace Preserved"
        }

@router.get("/baselines/{asset_id}", summary="Get Radio & Synthetic MUD Baseline for Asset")
def get_baseline(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset {asset_id} not found in tenant scope."
            )

        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id, tenant_id=tenant_id).first()
        if not baseline:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No behavioral baseline exists yet for asset {asset_id}."
            )

        summary = json.loads(baseline.summary_json or '{}')

        return {
            "id": baseline.id,
            "tenant_id": baseline.tenant_id,
            "asset_id": baseline.asset_id,
            "status": baseline.status,
            "maturity_stage": summary.get("maturity_stage", "PRELIMINARY"),
            "maturity_confidence": summary.get("maturity_confidence", 0.35),
            "evidence_window": summary.get("evidence_window", "0.0 minutes"),
            "observation_count": summary.get("observation_count", 0),
            "radio_profile": {
                "rssi_current": summary.get("rssi_current"),
                "rssi_mean": summary.get("rssi_mean"),
                "rssi_min": summary.get("rssi_min"),
                "rssi_max": summary.get("rssi_max"),
                "rssi_ema": summary.get("rssi_ema"),
                "proximity_zone": summary.get("proximity_zone", "NEAR_RANGE"),
                "proximity_trend": summary.get("proximity_trend", "STABLE"),
                "primary_channel": summary.get("primary_channel"),
                "primary_ssid": summary.get("primary_ssid"),
                "persistence_score": summary.get("persistence_score", 0.5),
                "activity_state": summary.get("activity_state", "ACTIVE_TRANSMITTING")
            },
            "allowed_destinations": json.loads(baseline.allowed_destinations or "[]"),
            "allowed_ports": json.loads(baseline.allowed_ports or "[]"),
            "allowed_protocols": json.loads(baseline.allowed_protocols or "[]"),
            "dns_whitelist": json.loads(baseline.dns_whitelist or "[]"),
            "learning_start": baseline.learning_start.isoformat() if baseline.learning_start else None,
            "learning_end": baseline.learning_end.isoformat() if baseline.learning_end else None,
            "last_updated": baseline.last_updated.isoformat() if baseline.last_updated else None
        }

@router.get("/drift", response_model=DriftFeedResponse, summary="List Behavioral Drift Anomalies")
def list_drifts(
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        query = BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id)
        if severity:
            query = query.filter_by(severity=severity.lower())

        total_count = query.count()
        items = query.order_by(BehavioralDriftEvent.created_at.desc()).offset(offset).limit(limit).all()

        result_items = []
        for d in items:
            result_items.append(BehavioralDriftResponse(
                id=d.id,
                tenant_id=d.tenant_id,
                asset_id=d.asset_id,
                drift_type=d.drift_type,
                severity=d.severity,
                difference=d.difference_description,
                confidence=d.confidence or 0.8,
                status=d.status,
                created_at=d.created_at
            ))

        return DriftFeedResponse(items=result_items, total_count=total_count)
