"""
AuthGuard Canonical Finding Model
=================================
Defines standardized security vulnerability records with CVSS scores,
validation statuses, remediation instructions, and test references.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.models.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    test_case_id = Column(Integer, ForeignKey("test_cases.id"), nullable=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    module = Column(String(32), nullable=False, index=True)  # otp, rate_limit, captcha
    affected_endpoint = Column(String(512), nullable=False)

    # Severity: Critical, High, Medium, Low, Informational
    severity = Column(String(32), nullable=False, index=True)
    cvss_score = Column(Float, default=0.0)
    cwe_id = Column(String(32), nullable=True)

    # Confidence: Confirmed, Suspected, Inconclusive
    confidence = Column(String(32), default="Confirmed", nullable=False)

    # Validation Status: Confirmed, Suspected, Inconclusive, False positive, Resolved, Accepted risk
    validation_status = Column(String(32), default="Confirmed", nullable=False, index=True)

    expected_behavior = Column(Text, nullable=False)
    actual_behavior = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    # Retest Status: Not retested, Retest passed, Retest failed
    retest_status = Column(String(32), default="Not retested")

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    assessment = relationship("Assessment", back_populates="findings")
    test_case = relationship("TestCase", back_populates="findings")
    evidence_records = relationship("EvidenceRecord", back_populates="finding", cascade="all, delete-orphan")
