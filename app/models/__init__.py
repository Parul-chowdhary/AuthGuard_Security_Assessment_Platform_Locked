"""
AuthGuard Database Models Namespace
===================================
Exports all SQLAlchemy ORM models for unified registry discovery.
"""

from app.models.base import Base, engine, SessionLocal, get_db, init_db
from app.models.user import User
from app.models.target import Target
from app.models.assessment import Assessment, TestCase
from app.models.finding import Finding
from app.models.evidence import EvidenceRecord
from app.models.report import Report, AuditLog

__all__ = [
    "Base",
    "engine",
    "SessionLocal",
    "get_db",
    "init_db",
    "User",
    "Target",
    "Assessment",
    "TestCase",
    "Finding",
    "EvidenceRecord",
    "Report",
    "AuditLog",
]
