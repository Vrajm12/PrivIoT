"""
FastAPI Asset Inventory & Device Trust Profile Router
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, Asset
from priviot.api.schemas.assets import AssetResponse, AssetListResponse, TrustProfileResponse

router = APIRouter(prefix="/api/v2/assets", tags=["Asset Inventory & Trust Profiles"])

@router.get("", response_model=AssetListResponse, summary="List Multi-Tenant Assets")
def list_assets(
    severity: Optional[str] = None,
    drift: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    List all discovered network assets within the current tenant boundary.
    """
    query = Asset.query.filter_by(tenant_id=tenant_id)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Asset.ip_address.ilike(search_pattern)) |
            (Asset.mac_address.ilike(search_pattern)) |
            (Asset.vendor.ilike(search_pattern)) |
            (Asset.model.ilike(search_pattern)) |
            (Asset.hostname.ilike(search_pattern))
        )

    total_count = query.count()
    items = query.order_by(Asset.last_seen.desc().nullslast()).offset(offset).limit(limit).all()

    # Map to schema response
    result_items = []
    for a in items:
        resp = AssetResponse(
            id=a.id,
            tenant_id=a.tenant_id,
            ip_address=a.ip_address,
            mac_address=a.mac_address,
            hostname=a.hostname,
            vendor=a.vendor or "Unknown",
            model=a.model or "Unknown",
            device_type=a.device_type or "Unknown IoT",
            firmware_version=a.firmware_version,
            identity_confidence=a.identity_confidence or 0.5,
            network_scope=a.network_scope or "192.168.1.0/24",
            is_managed=getattr(a, "is_managed", a.lifecycle_status == "active"),
            current_pri_score=a.get_latest_risk().pri_score if a.get_latest_risk() else 2.0,
            pri_risk_level=a.get_latest_risk().pri_level if a.get_latest_risk() else "low",
            behavioral_state=a.get_active_baseline().status if a.get_active_baseline() else "STABLE",
            active_containment_state=a.get_active_containment().status if a.get_active_containment() else "UNCONTAINED",
            first_seen=a.first_seen,
            last_seen=a.last_seen
        )
        result_items.append(resp)

    return AssetListResponse(items=result_items, total_count=total_count)

@router.get("/{asset_id}", response_model=AssetResponse, summary="Get Asset Details")
def get_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Retrieve single asset details with strict server-side tenant isolation.
    """
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found in tenant scope."
        )

    return AssetResponse(
        id=asset.id,
        tenant_id=asset.tenant_id,
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        hostname=asset.hostname,
        vendor=asset.vendor or "Unknown",
        model=asset.model or "Unknown",
        device_type=asset.device_type or "Unknown IoT",
        firmware_version=asset.firmware_version,
        identity_confidence=asset.identity_confidence or 0.5,
        network_scope=asset.network_scope or "192.168.1.0/24",
        is_managed=getattr(asset, "is_managed", asset.lifecycle_status == "active"),
        current_pri_score=asset.get_latest_risk().pri_score if asset.get_latest_risk() else 2.0,
        pri_risk_level=asset.get_latest_risk().pri_level if asset.get_latest_risk() else "low",
        behavioral_state=asset.get_active_baseline().status if asset.get_active_baseline() else "STABLE",
        active_containment_state=asset.get_active_containment().status if asset.get_active_containment() else "UNCONTAINED",
        first_seen=asset.first_seen,
        last_seen=asset.last_seen
    )

@router.get("/{asset_id}/trust-profile", response_model=TrustProfileResponse, summary="Get Flagship Device Trust Profile")
def get_asset_trust_profile(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Returns canonical 11-category Device Trust Profile for the asset.
    """
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found in tenant scope."
        )

    profile = asset.get_trust_profile()
    return TrustProfileResponse(
        asset_id=asset.id,
        tenant_id=asset.tenant_id,
        profile=profile
    )
