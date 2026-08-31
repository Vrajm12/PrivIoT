"""
FastAPI Alerts & Incident Triage Router
"""
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from extensions import db
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, Alert
from priviot.api.schemas.alerts import AlertResponse, AlertListResponse, AlertActionRequest
from priviot.api.schemas.common import GenericSuccessResponse

router = APIRouter(prefix="/api/v2/alerts", tags=["Alerts & Threat Incidents"])

@router.get("", response_model=AlertListResponse, summary="List Tenant Alerts")
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    List deterministic security alerts for the current tenant.
    """
    query = Alert.query.filter_by(tenant_id=tenant_id)
    if status_filter:
        query = query.filter_by(status=status_filter.upper())
    if severity:
        query = query.filter_by(severity=severity.lower())

    total_count = query.count()
    items = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()

    result_items = []
    for al in items:
        resp = AlertResponse(
            id=al.id,
            alert_uuid=al.alert_uuid,
            tenant_id=al.tenant_id,
            asset_id=al.asset_id,
            alert_type=al.alert_type,
            severity=al.severity,
            title=al.title,
            description=al.description,
            evidence=al.to_dict().get("evidence", {}),
            status=al.status,
            created_at=al.created_at,
            resolved_at=al.resolved_at
        )
        result_items.append(resp)

    return AlertListResponse(items=result_items, total_count=total_count)

@router.get("/{alert_id}", response_model=AlertResponse, summary="Get Alert Incident Detail")
def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Get deep-dive evidence for a specific security alert with tenant isolation.
    """
    alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found in tenant scope."
        )

    return AlertResponse(
        id=alert.id,
        alert_uuid=alert.alert_uuid,
        tenant_id=alert.tenant_id,
        asset_id=alert.asset_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        evidence=alert.to_dict().get("evidence", {}),
        status=alert.status,
        created_at=alert.created_at,
        resolved_at=alert.resolved_at
    )

@router.post("/{alert_id}/acknowledge", response_model=GenericSuccessResponse, summary="Acknowledge Alert")
def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = "ACKNOWLEDGED"
    db.session.commit()
    return GenericSuccessResponse(message=f"Alert {alert_id} acknowledged.")

@router.post("/{alert_id}/resolve", response_model=GenericSuccessResponse, summary="Resolve Alert")
def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = "RESOLVED"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by_id = current_user.id
    db.session.commit()
    return GenericSuccessResponse(message=f"Alert {alert_id} resolved.")
