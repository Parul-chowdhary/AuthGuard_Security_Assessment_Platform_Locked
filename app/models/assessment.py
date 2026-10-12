"""
AuthGuard Assessment & Test Execution Models
============================================
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, JSON, Float
from sqlalchemy.orm import relationship
from app.models.base import Base


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # State: pending, running, completed, failed, cancelled
    status = Column(String(32), default="pending", nullable=False, index=True)
    current_phase = Column(String(64), default="initialized")
    
    # Progress & Metrics
    total_tests = Column(Integer, default=0)
    completed_tests = Column(Integer, default=0)
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)
    inconclusive_tests = Column(Integer, default=0)
    
    # Safety Budgets
    request_budget = Column(Integer, default=250)
    requests_used = Column(Integer, default=0)
    
    # Configuration JSON: selected modules, test accounts, rate limit settings
    config = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    creator = relationship("User", back_populates="assessments")
    target = relationship("Target", back_populates="assessments")
    test_cases = relationship("TestCase", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="assessment", cascade="all, delete-orphan")


class TestCase(Base):
    __tablename__ = "test_cases"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    module = Column(String(32), nullable=False, index=True)  # otp, rate_limit, captcha
    test_code = Column(String(64), nullable=False)          # e.g., OTP-001, RL-002, CAP-001
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    
    # Outcome: pending, running, passed, failed, inconclusive, skipped
    status = Column(String(32), default="pending", nullable=False)
    details = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    assessment = relationship("Assessment", back_populates="test_cases")
    findings = relationship("Finding", back_populates="test_case")
