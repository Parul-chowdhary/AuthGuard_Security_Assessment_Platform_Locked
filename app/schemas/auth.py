"""
AuthGuard Authentication & User Pydantic Schemas
================================================
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    role: Optional[str] = "auditor"


class UserLoginSchema(BaseModel):
    username: str
    password: str


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
