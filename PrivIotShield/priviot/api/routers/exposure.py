"""
FastAPI Exposure & PRI-v2 Calculator Router
"""
from fastapi import APIRouter, Depends
from priviot.api.dependencies import get_current_user
from priviot.data.models import User
from priviot.engines.exposure import exposure_engine
from priviot.api.schemas.exposure import PriCalculationRequest, PriCalculationResponse

router = APIRouter(prefix="/api/v2/exposure", tags=["Exposure & PRI-v2 Risk Model"])

@router.post("/calculate-pri", response_model=PriCalculationResponse, summary="Calculate Explainable PRI-v2 Risk Index")
def calculate_pri(
    req: PriCalculationRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Direct endpoint for PRI-v2 mathematical scoring and explainability factors.
    """
    asset_dict = {
        "vendor": req.vendor,
        "model": req.model,
        "device_type": req.device_type,
        "criticality": "high"
    }

    # Delegate directly to pure domain exposure_engine
    result = exposure_engine.calculate_pri(
        asset_dict=asset_dict,
        vulnerabilities=req.vulnerabilities,
        network_placement=req.network_placement,
        behavioral_penalties=req.behavioral_penalties,
        compliance_penalties=req.compliance_penalties
    )

    return PriCalculationResponse(
        pri_score=result.get("pri_score", 2.0),
        risk_level=result.get("pri_level", "low"),
        threat_base=result.get("threat_base", 2.0),
        cisa_kev_boost=result.get("cisa_kev_boost", 0.0),
        epss_signal=result.get("epss_signal", 0.0),
        exposure_factor=result.get("exposure_factor", 0.4),
        behavioral_penalties=result.get("behavioral_penalty", 0.0),
        compliance_penalties=result.get("compliance_penalty", 0.0),
        explainability=result.get("explanation", {})
    )
