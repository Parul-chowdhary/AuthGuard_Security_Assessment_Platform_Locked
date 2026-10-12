"""
AuthGuard Assessment Management API
===================================
Endpoints for registering authorized targets, launching assessments,
polling live execution progress, and cancelling active jobs.
"""

import asyncio
from typing import List
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.assessment_engine.orchestrator import (
    request_assessment_cancellation,
    run_assessment_pipeline,
)
from app.core.scope import validate_target_url
from app.dependencies import get_current_user
from app.models.base import SessionLocal, get_db
from app.models.assessment import Assessment, TestCase
from app.models.finding import Finding
from app.models.report import AuditLog
from app.models.target import Target
from app.models.user import User
from app.schemas.assessment import (
    AssessmentCreateSchema,
    AssessmentResponseSchema,
    TargetCreateSchema,
    TargetResponseSchema,
)

router = APIRouter(prefix="/api", tags=["Assessments"])


# ---------------- Target Endpoints ----------------

@router.post("/targets", response_model=TargetResponseSchema)
def create_target(payload: TargetCreateSchema, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Validate target URL and SSRF bounds
    try:
        norm_url, hostname, ips = validate_target_url(
            payload.base_url,
            approved_hostnames=payload.approved_hostnames if payload.approved_hostnames else None,
            allow_local_for_testing=True,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    approved_list = payload.approved_hostnames or [hostname]
    if hostname not in approved_list:
        approved_list.append(hostname)

    target = Target(
        name=payload.name,
        base_url=norm_url,
        hostname=hostname,
        approved_hostnames=approved_list,
        permitted_endpoints=payload.permitted_endpoints,
        authorization_proof=payload.authorization_proof,
        created_by_id=current_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="TARGET_CREATE",
        resource_type="target",
        resource_id=str(target.id),
        details={"name": target.name, "hostname": target.hostname},
    )
    db.add(audit)
    db.commit()

    return target


@router.get("/targets", response_model=List[TargetResponseSchema])
def list_targets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Target).order_by(Target.created_at.desc()).all()


# ---------------- Assessment Endpoints ----------------

def _run_bg_assessment(assessment_id: int):
    """Background execution runner using isolated DB session."""
    db = SessionLocal()
    try:
        asyncio.run(run_assessment_pipeline(assessment_id, db))
    finally:
        db.close()


@router.post("/assessments", response_model=AssessmentResponseSchema)
def create_assessment(
    payload: AssessmentCreateSchema,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    assessment = Assessment(
        name=payload.name,
        target_id=target.id,
        created_by_id=current_user.id,
        status="pending",
        current_phase="Queued for execution",
        request_budget=payload.request_budget,
        config={
            "modules": payload.modules,
            "concurrency": payload.concurrency,
            "test_account_username": payload.test_account_username,
            "test_account_password": payload.test_account_password,
            "otp_endpoint": payload.otp_endpoint,
            "login_endpoint": payload.login_endpoint,
            "captcha_endpoint": payload.captcha_endpoint,
        },
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # Queue background task
    background_tasks.add_task(_run_bg_assessment, assessment.id)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="ASSESSMENT_LAUNCH",
        resource_type="assessment",
        resource_id=str(assessment.id),
        details={"name": assessment.name, "target_id": target.id},
    )
    db.add(audit)
    db.commit()

    return assessment


@router.get("/assessments", response_model=List[AssessmentResponseSchema])
def list_assessments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Assessment).order_by(Assessment.created_at.desc()).all()


@router.get("/assessments/{assessment_id}")
def get_assessment_details(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")

    test_cases = db.query(TestCase).filter(TestCase.assessment_id == assessment_id).all()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()

    return {
        "assessment": {
            "id": assessment.id,
            "name": assessment.name,
            "target": {
                "id": assessment.target.id,
                "name": assessment.target.name,
                "base_url": assessment.target.base_url,
                "hostname": assessment.target.hostname,
            },
            "status": assessment.status,
            "current_phase": assessment.current_phase,
            "total_tests": assessment.total_tests,
            "completed_tests": assessment.completed_tests,
            "passed_tests": assessment.passed_tests,
            "failed_tests": assessment.failed_tests,
            "inconclusive_tests": assessment.inconclusive_tests,
            "request_budget": assessment.request_budget,
            "requests_used": assessment.requests_used,
            "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
            "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
            "created_at": assessment.created_at.isoformat(),
            "error_message": assessment.error_message,
        },
        "test_cases": [
            {
                "id": tc.id,
                "module": tc.module,
                "test_code": tc.test_code,
                "name": tc.name,
                "status": tc.status,
                "details": tc.details,
            }
            for tc in test_cases
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "module": f.module,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "affected_endpoint": f.affected_endpoint,
                "validation_status": f.validation_status,
                "description": f.description,
            }
            for f in findings
        ],
    }


@router.post("/assessments/{assessment_id}/cancel")
def cancel_assessment(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")

    if assessment.status not in ("pending", "running"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Assessment is not currently active.")

    request_assessment_cancellation(assessment_id)
    assessment.status = "cancelled"
    assessment.current_phase = "Cancellation requested by user"
    db.commit()

    return {"status": "success", "message": f"Assessment {assessment_id} marked for cancellation."}
