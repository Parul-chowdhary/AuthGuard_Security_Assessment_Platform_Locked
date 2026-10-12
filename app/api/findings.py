"""
AuthGuard Findings Management API
=================================
Search, filter, paginate findings and manage triage statuses (Confirmed,
False positive, Resolved, Accepted risk).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models.base import get_db
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingResponseSchema, FindingStatusUpdateSchema

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("", response_model=List[FindingResponseSchema])
def list_findings(
    severity: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    validation_status: Optional[str] = Query(None),
    assessment_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity == severity)
    if module:
        query = query.filter(Finding.module == module)
    if validation_status:
        query = query.filter(Finding.validation_status == validation_status)
    if assessment_id:
        query = query.filter(Finding.assessment_id == assessment_id)

    return query.order_by(Finding.created_at.desc()).all()


@router.get("/{finding_id}", response_model=FindingResponseSchema)
def get_finding(finding_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponseSchema)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    finding.validation_status = payload.validation_status
    if payload.retest_status:
        finding.retest_status = payload.retest_status
    db.commit()
    db.refresh(finding)
    return finding
