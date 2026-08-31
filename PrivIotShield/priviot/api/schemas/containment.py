"""
Containment Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class ContainmentPreviewRequest(BaseModel):
    asset_id: int
    target_provider: str = Field("iptables", description="iptables, pihole, pfsense, unifi")
    action: str = Field("isolate", description="isolate, quarantine, sinkhole_dns")

class ContainmentActionRequest(BaseModel):
    intent_id: Optional[int] = None
    asset_id: Optional[int] = None
    target_provider: Optional[str] = "iptables"
    notes: Optional[str] = None

class ContainmentPolicyResponse(BaseModel):
    intent_id: Optional[int] = None
    asset_id: int
    tenant_id: str
    target_provider: str
    current_state: str
    verification_state: str
    generated_rules: List[str]
    safe_flows_preserved: List[str]
    rollback_ready: bool
    created_at: Optional[datetime] = None
