"""
FastAPI Dependencies — Authentication, Tenant Isolation, RBAC & Database Session
"""
from typing import Generator, Optional, Dict, Any
import hashlib
from fastapi import Request, Header, HTTPException, status, Depends
from extensions import db
from priviot.data.models import User, Collector
from priviot.security.rbac import get_role_level
from app import app as flask_app

def get_db():
    """Yield database session."""
    yield db.session

def get_current_tenant(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_tenant_override: Optional[str] = Header(None, alias="X-Tenant")
) -> str:
    """
    Extract tenant context from request headers with safe default.
    """
    tenant = x_tenant_id or x_tenant_override
    if not tenant:
        return "default_tenant"
    # Basic sanitization
    return tenant.strip().lower()

def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    tenant_id: str = Depends(get_current_tenant)
) -> User:
    """
    Authenticate operator via API Key or Bearer Token with fallback to pilot admin.
    """
    with flask_app.app_context():
        # 1. API Key Auth
        if x_api_key is not None:
            if not x_api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Empty API Key provided."
                )
            user = User.query.filter_by(api_key=x_api_key).first()
            if user and user.is_active:
                user.active_tenant = tenant_id
                return user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API Key."
            )

        # 2. Bearer Token Auth
        if authorization is not None:
            if not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Authorization header format."
                )
            token = authorization.split(" ")[1]
            user = User.query.filter_by(api_key=token).first()
            if user and user.is_active:
                user.active_tenant = tenant_id
                return user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked Bearer token."
            )

        # 3. If no credentials provided at all
        admin_user = User.query.filter_by(username="admin").first()
        if admin_user:
            admin_user.active_tenant = tenant_id
            return admin_user

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials."
        )

def require_role(min_role: str):
    """
    Enforce server-side RBAC minimum role requirement.
    """
    def rbac_checker(user: User = Depends(get_current_user)) -> User:
        user_role = getattr(user, "role", "viewer")
        if get_role_level(user_role) < get_role_level(min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action requires '{min_role.upper()}' role or higher."
            )
        return user
    return rbac_checker

def get_authenticated_collector(
    x_sensor_token: Optional[str] = Header(None, alias="X-Sensor-Token"),
    authorization: Optional[str] = Header(None),
    tenant_id: str = Depends(get_current_tenant)
) -> Collector:
    """
    Verify edge collector authentication token using telemetry_engine.
    """
    raw_token = x_sensor_token
    if not raw_token and authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ")[1]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing collector authentication token (X-Sensor-Token)."
        )

    from priviot.engines.telemetry import telemetry_engine
    collector = telemetry_engine.authenticate_collector(raw_token)

    if not collector:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked collector authentication token."
        )

    return collector

