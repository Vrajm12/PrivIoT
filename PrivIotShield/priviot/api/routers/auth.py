"""
FastAPI Authentication & Session Router
"""
from fastapi import APIRouter, Depends, HTTPException, status
from werkzeug.security import check_password_hash
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User
from priviot.api.schemas.auth import LoginRequest, TokenResponse, OperatorProfile

router = APIRouter(prefix="/api/v2/auth", tags=["Operator Authentication"])

@router.post("/login", response_model=TokenResponse, summary="Operator Login (API Key / Token Generation)")
def login(
    req: LoginRequest,
    tenant_id: str = Depends(get_current_tenant)
):
    user = User.query.filter_by(username=req.username).first()
    if not user or not check_password_hash(user.password_hash, req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password credentials."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator account is inactive."
        )

    return TokenResponse(
        access_token=user.api_key,
        token_type="bearer",
        role=user.role,
        tenant_id=tenant_id,
        username=user.username
    )

@router.get("/me", response_model=OperatorProfile, summary="Current Operator Identity")
def get_me(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    return OperatorProfile(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        tenant_id=tenant_id,
        is_active=current_user.is_active
    )
