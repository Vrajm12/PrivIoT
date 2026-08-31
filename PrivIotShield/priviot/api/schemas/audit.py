"""
Audit Log Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AuditEventResponse(BaseModel):
    id: int
    tenant_id: str
    actor: str
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    request_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    result: str = "success"
    timestamp: Optional[datetime] = None

    class Config:
        from_attributes = True

class AuditListResponse(BaseModel):
    items: List[AuditEventResponse]
    total_count: int
