"""
Auth & Session Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    tenant_id: str
    username: str

class OperatorProfile(BaseModel):
    id: int
    username: str
    email: str
    role: str
    tenant_id: str
    is_active: bool
