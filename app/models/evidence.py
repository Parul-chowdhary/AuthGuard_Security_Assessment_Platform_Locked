"""
AuthGuard Evidence Management Database Models
==============================================
Maintains sanitized HTTP request/response artifacts with integrity verification hashes.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.models.base import Base


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True, index=True)
    test_case_id = Column(Integer, ForeignKey("test_cases.id"), nullable=True)

    endpoint = Column(String(512), nullable=False)
    http_method = Column(String(16), default="POST", nullable=False)
    
    # Sanitized request artifacts (secrets redacted)
    sanitized_request_headers = Column(JSON, default=dict)
    sanitized_request_body = Column(Text, nullable=True)
    
    # Sanitized response artifacts
    sanitized_response_status = Column(Integer, nullable=False)
    sanitized_response_headers = Column(JSON, default=dict)
    sanitized_response_body = Column(Text, nullable=True)
    
    # Cryptographic integrity hash (SHA256 of sanitized payload)
    integrity_hash = Column(String(64), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    finding = relationship("Finding", back_populates="evidence_records")
