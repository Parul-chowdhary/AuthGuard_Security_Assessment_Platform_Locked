"""
AuthGuard Target & Scope Database Models
========================================
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.models.base import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    base_url = Column(String(512), nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    approved_hostnames = Column(JSON, default=list)  # List of approved hostnames/domains
    permitted_endpoints = Column(JSON, default=list)  # List of allowed paths (e.g. /login, /verify-otp)
    authorization_proof = Column(Text, nullable=True)  # Cryptographic token or signed authorization reference
    is_active = Column(Boolean, default=True, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    creator = relationship("User", back_populates="targets")
    assessments = relationship("Assessment", back_populates="target", cascade="all, delete-orphan")
