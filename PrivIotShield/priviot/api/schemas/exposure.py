"""
Exposure & PRI-v2 Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class PriCalculationRequest(BaseModel):
    asset_id: Optional[int] = None
    vendor: str = "Generic"
    model: str = "IoT Device"
    device_type: str = "Smart Camera"
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    network_placement: str = "flat_lan"
    behavioral_penalties: float = 0.0
    compliance_penalties: float = 0.0

class PriCalculationResponse(BaseModel):
    pri_score: float = Field(..., ge=1.0, le=10.0)
    risk_level: str
    threat_base: float
    cisa_kev_boost: float
    epss_signal: float
    exposure_factor: float
    behavioral_penalties: float
    compliance_penalties: float
    explainability: Dict[str, Any]
