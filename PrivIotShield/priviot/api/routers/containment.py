"""
FastAPI Micro-Segmentation & Containment Lifecycle Router
"""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from extensions import db
from priviot.api.dependencies import get_current_user, get_current_tenant, require_role
from priviot.data.models import User, Asset, ContainmentIntent, AuditEvent
from priviot.engines.containment import containment_engine
from priviot.api.schemas.containment import (
    ContainmentPreviewRequest, ContainmentActionRequest, ContainmentPolicyResponse
)
from priviot.api.schemas.common import GenericSuccessResponse

router = APIRouter(prefix="/api/v2/containment", tags=["Micro-Segmentation & Containment"])

@router.post("/preview", response_model=ContainmentPolicyResponse, summary="Generate Containment Preview & Rule Set")
def preview_containment(
    req: ContainmentPreviewRequest,
    current_user: User = Depends(require_role("operator")),
    tenant_id: str = Depends(get_current_tenant)
):
    asset = Asset.query.filter_by(id=req.asset_id, tenant_id=tenant_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {req.asset_id} not found in tenant scope."
        )

    latest_risk = asset.get_latest_risk()
    pri_data = latest_risk.to_dict() if latest_risk else {"pri_score": 7.0, "pri_level": "high"}
    
    intent_data = containment_engine.create_intent_for_asset(asset, pri_data)
    try:
        preview = containment_engine.preview_containment(
            intent_data, asset.ip_address, provider_name=req.target_provider
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    # Persist or update ContainmentIntent record in PREVIEWED state
    intent = asset.get_active_containment()
    if not intent:
        intent = ContainmentIntent(
            tenant_id=tenant_id,
            asset_id=asset.id,
            reason=intent_data["reason"],
            severity=intent_data["severity"],
            desired_effect=intent_data["desired_effect"],
            allowed_destinations=json.dumps(intent_data["allowed_destinations"]),
            blocked_destinations=json.dumps(intent_data["blocked_destinations"]),
            allowed_ports=json.dumps(intent_data["allowed_ports"]),
            blocked_ports=json.dumps(intent_data["blocked_ports"]),
            protocol=intent_data["protocol"],
            status="PREVIEWED",
            applied_provider=req.target_provider,
            generated_policy=preview.get("proposed_policy", ""),
            rollback_policy=preview.get("rollback_policy", ""),
            rollback_limitation=preview.get("rollback_limitation")
        )
        db.session.add(intent)
    else:
        intent.status = "PREVIEWED"
        intent.applied_provider = req.target_provider
        intent.generated_policy = preview.get("proposed_policy", "")
        intent.rollback_policy = preview.get("rollback_policy", "")
        intent.rollback_limitation = preview.get("rollback_limitation")

    audit = AuditEvent(
        tenant_id=tenant_id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="containment_previewed",
        target_type="asset",
        target_id=str(asset.id),
        details_json=json.dumps({"provider": req.target_provider, "ip": asset.ip_address}),
        result="success"
    )
    db.session.add(audit)
    db.session.commit()

    return ContainmentPolicyResponse(
        intent_id=intent.id,
        asset_id=asset.id,
        tenant_id=tenant_id,
        target_provider=req.target_provider,
        current_state="PREVIEWED",
        verification_state="UNVERIFIED",
        generated_rules=preview.get("proposed_policy", "").split("\n"),
        safe_flows_preserved=intent_data.get("allowed_destinations", []),
        rollback_ready=True,
        created_at=intent.created_at
    )

@router.post("/approve", response_model=GenericSuccessResponse, summary="Authorize Containment (Multi-Party Approval)")
def approve_containment(
    req: ContainmentActionRequest,
    current_user: User = Depends(require_role("approver")),
    tenant_id: str = Depends(get_current_tenant)
):
    if not req.intent_id and not req.asset_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="intent_id or asset_id is required")

    intent = None
    if req.intent_id:
        intent = ContainmentIntent.query.filter_by(id=req.intent_id, tenant_id=tenant_id).first()
    elif req.asset_id:
        asset = Asset.query.filter_by(id=req.asset_id, tenant_id=tenant_id).first()
        if asset:
            intent = asset.get_active_containment()

    if not intent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ContainmentIntent not found")

    intent.status = containment_engine.transition_state(intent.status, "APPROVED")
    intent.approved_by_id = current_user.id
    
    audit = AuditEvent(
        tenant_id=tenant_id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="containment_approved",
        target_type="containment",
        target_id=str(intent.id),
        details_json=json.dumps({"intent_id": intent.id, "approved_by": current_user.username}),
        result="success"
    )
    db.session.add(audit)
    db.session.commit()

    return GenericSuccessResponse(message=f"Containment intent {intent.id} successfully approved by {current_user.username}.")

@router.post("/apply", response_model=GenericSuccessResponse, summary="Execute Containment at Network Gateway")
def apply_containment(
    req: ContainmentActionRequest,
    current_user: User = Depends(require_role("operator")),
    tenant_id: str = Depends(get_current_tenant)
):
    if not req.intent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="intent_id is required")

    intent = ContainmentIntent.query.filter_by(id=req.intent_id, tenant_id=tenant_id).first()
    if not intent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ContainmentIntent not found")

    asset = Asset.query.filter_by(id=intent.asset_id, tenant_id=tenant_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated asset not found")

    # State machine transition
    intent.status = containment_engine.transition_state(intent.status, "APPLYING")
    
    # Execute apply on provider
    res = containment_engine.execute_apply(
        intent_dict=intent.to_dict(),
        ip_address=asset.ip_address,
        provider_name=intent.applied_provider or "iptables"
    )

    if res.get("success"):
        intent.status = containment_engine.transition_state("APPLYING", "VERIFIED")
        intent.executed_at = datetime.utcnow()
    else:
        intent.status = "FAILED"

    audit = AuditEvent(
        tenant_id=tenant_id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="containment_applied",
        target_type="containment",
        target_id=str(intent.id),
        details_json=json.dumps({"intent_id": intent.id, "provider": intent.applied_provider, "status": intent.status}),
        result="success" if res.get("success") else "failure"
    )
    db.session.add(audit)
    db.session.commit()

    return GenericSuccessResponse(message=f"Containment applied with status: {intent.status}")

@router.post("/rollback", response_model=GenericSuccessResponse, summary="1-Click Containment Rollback")
def rollback_containment(
    req: ContainmentActionRequest,
    current_user: User = Depends(require_role("operator")),
    tenant_id: str = Depends(get_current_tenant)
):
    if not req.intent_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="intent_id is required")

    intent = ContainmentIntent.query.filter_by(id=req.intent_id, tenant_id=tenant_id).first()
    if not intent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ContainmentIntent not found")

    asset = Asset.query.filter_by(id=intent.asset_id, tenant_id=tenant_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated asset not found")

    # State machine transition
    intent.status = containment_engine.transition_state(intent.status, "ROLLBACK_REQUESTED")
    intent.status = containment_engine.transition_state("ROLLBACK_REQUESTED", "ROLLING_BACK")

    res = containment_engine.execute_rollback(
        intent_dict=intent.to_dict(),
        ip_address=asset.ip_address,
        provider_name=intent.applied_provider or "iptables"
    )

    if res.get("success"):
        intent.status = containment_engine.transition_state("ROLLING_BACK", "ROLLED_BACK")
    else:
        intent.status = "ROLLBACK_FAILED"

    audit = AuditEvent(
        tenant_id=tenant_id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="containment_rolled_back",
        target_type="containment",
        target_id=str(intent.id),
        details_json=json.dumps({"intent_id": intent.id, "provider": intent.applied_provider, "status": intent.status}),
        result="success" if res.get("success") else "failure"
    )
    db.session.add(audit)
    db.session.commit()

    return GenericSuccessResponse(message=f"Containment rollback completed with status: {intent.status}")
