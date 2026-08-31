"""
Alerts Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AlertResponse(BaseModel):
    id: int
    alert_uuid: str
    tenant_id: str
    asset_id: Optional[int] = None
    alert_type: str
    severity: str
    title: str
    description: str
    evidence: Optional[Dict[str, Any]] = None
    status: str
    created_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total_count: int

class AlertActionRequest(BaseModel):
    action: str = Field(..., description="Action to perform: ACKNOWLEDGE, RESOLVE, SUPPRESS")
    notes: Optional[str] = None
