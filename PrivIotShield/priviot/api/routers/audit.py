"""
FastAPI Immutable Audit Trail Router
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, AuditEvent
from priviot.api.schemas.audit import AuditEventResponse, AuditListResponse

router = APIRouter(prefix="/api/v2/audit", tags=["Immutable Audit Trail"])

@router.get("", response_model=AuditListResponse, summary="Query Tenant Audit Events")
def list_audit_events(
    action: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    query = AuditEvent.query.filter_by(tenant_id=tenant_id)
    if action:
        query = query.filter_by(action=action)

    total_count = query.count()
    items = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()

    result_items = []
    for a in items:
        result_items.append(AuditEventResponse(
            id=a.id,
            tenant_id=a.tenant_id,
            actor=a.actor_username,
            action=a.action,
            target_type=a.target_type,
            target_id=a.target_id,
            request_id=a.request_id,
            details=a.to_dict().get("details", {}),
            result=a.result,
            timestamp=a.timestamp
        ))

    return AuditListResponse(items=result_items, total_count=total_count)
