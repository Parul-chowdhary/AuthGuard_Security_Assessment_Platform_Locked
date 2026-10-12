"""
AuthGuard Dashboard Analytics API
=================================
Provides real-time aggregated metrics, module test coverage,
finding distributions by severity, and recent audit activity.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.dependencies import get_current_user
from app.models.base import get_db
from app.models.assessment import Assessment, TestCase
from app.models.finding import Finding
from app.models.report import AuditLog
from app.models.user import User

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
def get_dashboard_statistics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Assessment counts
    total_assessments = db.query(Assessment).count()
    completed_assessments = db.query(Assessment).filter(Assessment.status == "completed").count()
    running_assessments = db.query(Assessment).filter(Assessment.status == "running").count()
    failed_assessments = db.query(Assessment).filter(Assessment.status == "failed").count()
    cancelled_assessments = db.query(Assessment).filter(Assessment.status == "cancelled").count()

    # 2. Findings by severity
    findings_q = db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
    findings_by_severity = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    total_findings = 0
    for sev, count in findings_q:
        if sev in findings_by_severity:
            findings_by_severity[sev] = count
            total_findings += count

    # 3. Module Coverage (number of test executions per module)
    coverage_q = db.query(TestCase.module, func.count(TestCase.id)).group_by(TestCase.module).all()
    module_coverage = {"otp": 0, "rate_limit": 0, "captcha": 0}
    for mod, count in coverage_q:
        if mod in module_coverage:
            module_coverage[mod] = count

    # 4. Recent assessments
    recent_assessments = (
        db.query(Assessment)
        .order_by(Assessment.created_at.desc())
        .limit(5)
        .all()
    )

    # 5. Recent audit activity
    recent_activity = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(8)
        .all()
    )

    return {
        "assessments": {
            "total": total_assessments,
            "completed": completed_assessments,
            "running": running_assessments,
            "failed": failed_assessments,
            "cancelled": cancelled_assessments,
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity,
        },
        "module_coverage": module_coverage,
        "recent_assessments": [
            {
                "id": a.id,
                "name": a.name,
                "target": a.target.name if a.target else "N/A",
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_assessments
        ],
        "recent_activity": [
            {
                "id": act.id,
                "action": act.action,
                "created_at": act.created_at.isoformat(),
            }
            for act in recent_activity
        ],
    }
