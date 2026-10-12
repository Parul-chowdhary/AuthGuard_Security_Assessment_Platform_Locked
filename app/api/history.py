"""
AuthGuard Assessment History & Retest Tracking API
==================================================
Compares findings across assessments to detect new, recurring, and resolved vulnerabilities.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models.base import get_db
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.user import User

router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("/compare")
def compare_assessments(
    base_id: int = Query(..., description="Earlier baseline assessment ID"),
    target_id: int = Query(..., description="Recent assessment ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base_asm = db.query(Assessment).filter(Assessment.id == base_id).first()
    target_asm = db.query(Assessment).filter(Assessment.id == target_id).first()

    if not base_asm or not target_asm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both assessments not found.")

    base_findings = db.query(Finding).filter(Finding.assessment_id == base_id).all()
    target_findings = db.query(Finding).filter(Finding.assessment_id == target_id).all()

    base_titles = {f.title: f for f in base_findings}
    target_titles = {f.title: f for f in target_findings}

    recurring = []
    resolved = []
    new_findings = []

    for title, f in target_titles.items():
        if title in base_titles:
            recurring.append({
                "title": f.title,
                "severity": f.severity,
                "endpoint": f.affected_endpoint,
            })
        else:
            new_findings.append({
                "title": f.title,
                "severity": f.severity,
                "endpoint": f.affected_endpoint,
            })

    for title, f in base_titles.items():
        if title not in target_titles:
            resolved.append({
                "title": f.title,
                "severity": f.severity,
                "endpoint": f.affected_endpoint,
            })

    return {
        "base_assessment": {"id": base_asm.id, "name": base_asm.name, "created_at": base_asm.created_at.isoformat()},
        "target_assessment": {"id": target_asm.id, "name": target_asm.name, "created_at": target_asm.created_at.isoformat()},
        "comparison": {
            "new_count": len(new_findings),
            "recurring_count": len(recurring),
            "resolved_count": len(resolved),
            "new_findings": new_findings,
            "recurring_findings": recurring,
            "resolved_findings": resolved,
        },
    }
