"""
FastAPI Collector Fleet Router
"""
from fastapi import APIRouter, Depends, HTTPException, status
from priviot.api.dependencies import get_current_user, get_current_tenant, require_role
from priviot.data.models import User, Collector
from priviot.services.collectors import collector_manager
from priviot.api.schemas.collectors import (
    CollectorEnrollRequest, CollectorResponse, CollectorEnrollResponse,
    CollectorListResponse, TokenRotationResponse
)

router = APIRouter(prefix="/api/v2/collectors", tags=["Collector Fleet Management"])

@router.get("", response_model=CollectorListResponse, summary="List Tenant Collector Sensors")
def list_collectors(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    query = Collector.query.filter_by(tenant_id=tenant_id)
    items = query.all()
    res_items = []
    for c in items:
        res_items.append(CollectorResponse(
            id=c.id,
            collector_uuid=c.collector_uuid,
            tenant_id=c.tenant_id,
            collector_name=getattr(c, "name", "Collector"),
            site_id=c.site_id,
            status=c.status,
            ingestion_rate=getattr(c, "ingestion_rate", 0.0) or 0.0,
            last_heartbeat=c.last_heartbeat,
            registered_at=c.created_at
        ))
    return CollectorListResponse(items=res_items, total_count=len(res_items))

@router.post("/register", response_model=CollectorEnrollResponse, summary="Enroll New Collector Sensor")
def register_collector(
    req: CollectorEnrollRequest,
    current_user: User = Depends(require_role("operator")),
    tenant_id: str = Depends(get_current_tenant)
):
    # Delegate to existing domain collector_manager
    collector, raw_token = collector_manager.enroll_collector(
        tenant_id=tenant_id,
        site_id=req.site_id or "default_site",
        name=req.collector_name
    )

    return CollectorEnrollResponse(
        id=collector.id,
        collector_uuid=collector.collector_uuid,
        tenant_id=collector.tenant_id,
        collector_name=getattr(collector, "name", "Collector"),
        site_id=collector.site_id,
        status=collector.status,
        ingestion_rate=getattr(collector, "ingestion_rate", 0.0) or 0.0,
        last_heartbeat=collector.last_heartbeat,
        registered_at=collector.created_at,
        raw_token=raw_token
    )

@router.post("/{collector_id}/rotate-token", response_model=TokenRotationResponse, summary="Rotate Sensor Pre-Shared Key")
def rotate_collector_token(
    collector_id: int,
    current_user: User = Depends(require_role("admin")),
    tenant_id: str = Depends(get_current_tenant)
):
    ok, new_token = collector_manager.rotate_token(
        collector_id=collector_id,
        tenant_id=tenant_id,
        actor_id=current_user.id
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector {collector_id} not found or token rotation failed."
        )

    return TokenRotationResponse(
        collector_id=collector_id,
        new_raw_token=new_token,
        message="Token successfully rotated. Deploy this new token to edge collector sensor."
    )
