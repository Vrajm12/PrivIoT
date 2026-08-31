"""
FastAPI Behavioral Baselines & Drift Feed Router
"""
from typing import Optional, List
import json
from fastapi import APIRouter, Depends, HTTPException, status, Query
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, Asset, BehavioralBaseline, BehavioralDriftEvent
from priviot.api.schemas.behavior import (
    BehavioralBaselineResponse, BehavioralDriftResponse, DriftFeedResponse
)

router = APIRouter(prefix="/api/v2/behavior", tags=["Behavioral Profiling & Drift"])

@router.get("/baselines/{asset_id}", response_model=BehavioralBaselineResponse, summary="Get 48-Hour Synthetic MUD Baseline")
def get_baseline(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
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

    return BehavioralBaselineResponse(
        id=baseline.id,
        tenant_id=baseline.tenant_id,
        asset_id=baseline.asset_id,
        status=baseline.status,
        allowed_destinations=json.loads(baseline.allowed_destinations or "[]"),
        allowed_ports=json.loads(baseline.allowed_ports or "[]"),
        allowed_protocols=json.loads(baseline.allowed_protocols or "[]"),
        dns_whitelist=json.loads(baseline.dns_whitelist or "[]"),
        learning_start=baseline.learning_start,
        learning_end=baseline.learning_end,
        last_updated=baseline.last_updated
    )

@router.get("/drift", response_model=DriftFeedResponse, summary="List Behavioral Drift Anomalies")
def list_drifts(
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
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
