"""
AuthGuard Evidence Management API
=================================
View sanitized HTTP evidence records with cryptographic integrity hashes.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models.base import get_db
from app.models.evidence import EvidenceRecord
from app.models.user import User

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])


@router.get("/{evidence_id}")
def get_evidence_record(evidence_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ev = db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found.")

    return {
        "id": ev.id,
        "assessment_id": ev.assessment_id,
        "finding_id": ev.finding_id,
        "test_case_id": ev.test_case_id,
        "endpoint": ev.endpoint,
        "http_method": ev.http_method,
        "sanitized_request_body": ev.sanitized_request_body,
        "sanitized_response_status": ev.sanitized_response_status,
        "sanitized_response_headers": ev.sanitized_response_headers,
        "sanitized_response_body": ev.sanitized_response_body,
        "integrity_hash": ev.integrity_hash,
        "created_at": ev.created_at.isoformat(),
    }
