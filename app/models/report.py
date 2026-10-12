"""
AuthGuard Report & Audit Database Models
========================================
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.models.base import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    report_format = Column(String(16), nullable=False)  # html, pdf, json
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 integrity hash
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    assessment = relationship("Assessment", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False, index=True)  # e.g., USER_LOGIN, ASSESSMENT_START, TARGET_CREATE
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(64), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
