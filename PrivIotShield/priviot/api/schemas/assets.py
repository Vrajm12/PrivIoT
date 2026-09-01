"""
Asset Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AssetBase(BaseModel):
    ip_address: str = Field(..., description="IP Address of the asset")
    mac_address: str = Field(..., description="MAC Hardware Address")
    hostname: Optional[str] = None
    vendor: Optional[str] = "Unknown"
    model: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown IoT"
    firmware_version: Optional[str] = None
    network_scope: Optional[str] = "192.168.1.0/24"
    is_managed: bool = True

class AssetResponse(AssetBase):
    id: int
    tenant_id: str
    identity_confidence: float = Field(..., ge=0.0, le=1.0)
    discovery_source: Optional[str] = "safe_active_probe"
    reconciliation_method: Optional[str] = "mac_address"
    current_pri_score: Optional[float] = 2.0
    pri_risk_level: Optional[str] = "low"
    behavioral_state: Optional[str] = "STABLE"
    active_containment_state: Optional[str] = "UNCONTAINED"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    rssi: Optional[int] = None
    channel: Optional[int] = None
    observation_count: Optional[int] = 0
    proximity_zone: Optional[str] = "NEAR_RANGE"
    maturity_stage: Optional[str] = "PRELIMINARY"
    maturity_confidence: Optional[float] = 0.35
    evidence_window: Optional[str] = "0.0 minutes"

    class Config:
        from_attributes = True

class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total_count: int

class TrustProfileResponse(BaseModel):
    asset_id: int
    tenant_id: str
    profile: Dict[str, Any]
