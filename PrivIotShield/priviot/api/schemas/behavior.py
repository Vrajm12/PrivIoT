"""
Behavioral Baseline & Drift Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class BehavioralBaselineResponse(BaseModel):
    id: int
    tenant_id: str
    asset_id: int
    status: str
    allowed_destinations: List[str]
    allowed_ports: List[int]
    allowed_protocols: List[str]
    dns_whitelist: List[str]
    learning_start: Optional[datetime] = None
    learning_end: Optional[datetime] = None
    last_updated: Optional[datetime] = None

    class Config:
        from_attributes = True

class BehavioralDriftResponse(BaseModel):
    id: int
    tenant_id: str
    asset_id: int
    drift_type: str
    severity: str
    difference: str
    confidence: float
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class DriftFeedResponse(BaseModel):
    items: List[BehavioralDriftResponse]
    total_count: int
