"""
PrivIoT Pydantic v2 Common Schemas & Error Contract
"""
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class ErrorDetail(BaseModel):
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable explanation")
    request_id: str = Field(..., description="Unique request correlation ID")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional context or validation errors")

class ErrorResponse(BaseModel):
    error: ErrorDetail

class PaginationMeta(BaseModel):
    total_count: int = Field(..., ge=0)
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
    total_pages: int = Field(..., ge=0)

class GenericSuccessResponse(BaseModel):
    success: bool = True
    message: str
    request_id: Optional[str] = None
