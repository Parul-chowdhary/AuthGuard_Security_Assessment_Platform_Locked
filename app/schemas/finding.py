"""
AuthGuard Finding & Report Pydantic Schemas
===========================================
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    title: str
    description: str
    module: str
    affected_endpoint: str
    severity: str
    cvss_score: float
    confidence: str
    validation_status: str
    expected_behavior: str
    actual_behavior: str
    potential_impact: str
    remediation: str
    retest_status: str
    created_at: datetime


class FindingStatusUpdateSchema(BaseModel):
    validation_status: str = Field(..., pattern=r"^(Confirmed|Suspected|Inconclusive|False positive|Resolved|Accepted risk)$")
    retest_status: Optional[str] = None


class ReportResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    report_format: str
    filename: str
    file_path: str
    file_hash: str
    created_at: datetime
