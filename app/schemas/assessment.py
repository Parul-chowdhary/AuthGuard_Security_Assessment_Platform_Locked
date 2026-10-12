"""
AuthGuard Assessment & Target Pydantic Schemas
==============================================
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TargetCreateSchema(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    base_url: str = Field(..., max_length=512)
    approved_hostnames: List[str] = Field(default_factory=list)
    permitted_endpoints: List[str] = Field(default_factory=lambda: ["/login", "/verify-otp", "/api/auth"])
    authorization_proof: Optional[str] = Field(default=None)


class TargetResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    base_url: str
    hostname: str
    approved_hostnames: List[str]
    permitted_endpoints: List[str]
    created_at: datetime


class AssessmentCreateSchema(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    target_id: int
    modules: List[str] = Field(default_factory=lambda: ["otp", "rate_limit", "captcha"])
    request_budget: int = Field(default=250, ge=10, le=1000)
    concurrency: int = Field(default=3, ge=1, le=10)
    test_account_username: Optional[str] = "testuser"
    test_account_password: Optional[str] = "TestPass123!"
    otp_endpoint: Optional[str] = "/verify-otp"
    login_endpoint: Optional[str] = "/login"
    captcha_endpoint: Optional[str] = "/login"


class AssessmentResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_id: int
    status: str
    current_phase: str
    total_tests: int
    completed_tests: int
    passed_tests: int
    failed_tests: int
    inconclusive_tests: int
    request_budget: int
    requests_used: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
