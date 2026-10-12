"""
AuthGuard Reports API
=====================
Download HTML, PDF, and JSON security assessment reports.
"""

from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.models.base import get_db
from app.models.report import Report
from app.models.user import User

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/{assessment_id}/{format}")
def download_report(
    assessment_id: int,
    format: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    format_lower = format.lower()
    if format_lower not in ("html", "pdf", "json"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Format must be html, pdf, or json.")

    report = (
        db.query(Report)
        .filter(Report.assessment_id == assessment_id, Report.report_format == format_lower)
        .order_by(Report.created_at.desc())
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No {format.upper()} report generated yet for assessment #{assessment_id}.",
        )

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on disk.")

    media_types = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json",
    }

    return FileResponse(
        path=str(file_path),
        filename=report.filename,
        media_type=media_types.get(format_lower, "application/octet-stream"),
    )
