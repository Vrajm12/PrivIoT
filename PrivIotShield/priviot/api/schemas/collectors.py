"""
Collector Fleet Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class CollectorEnrollRequest(BaseModel):
    collector_name: str = Field(..., min_length=2, max_length=64)
    site_id: Optional[str] = "default_site"
    ip_address: Optional[str] = None
    network_scope: Optional[str] = "192.168.1.0/24"

class CollectorResponse(BaseModel):
    id: int
    collector_uuid: str
    tenant_id: str
    collector_name: str
    site_id: str
    status: str
    ingestion_rate: float
    last_heartbeat: Optional[datetime] = None
    registered_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class CollectorEnrollResponse(CollectorResponse):
    raw_token: str = Field(..., description="Plaintext token shown ONCE at registration")

class CollectorListResponse(BaseModel):
    items: List[CollectorResponse]
    total_count: int

class TokenRotationResponse(BaseModel):
    collector_id: int
    new_raw_token: str
    message: str
