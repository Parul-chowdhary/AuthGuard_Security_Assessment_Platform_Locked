"""
AuthGuard Administration & System Health API
============================================
User role management, immutable audit logging viewer, and system diagnostics.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.permissions import PermissionEnum
from app.dependencies import get_current_user, require_permission
from app.models.base import get_db
from app.models.report import AuditLog
from app.models.user import User
from app.schemas.auth import UserResponseSchema

router = APIRouter(prefix="/api/admin", tags=["Administration"])


class RoleUpdateRequest(BaseModel):
    role: str


@router.get("/users", response_model=List[UserResponseSchema])
def list_all_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_permission(PermissionEnum.ADMIN_USERS)),
):
    return db.query(User).order_by(User.id.asc()).all()


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    payload: RoleUpdateRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_permission(PermissionEnum.ADMIN_USERS)),
):
    if payload.role not in ("admin", "auditor", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be 'admin', 'auditor', or 'viewer'.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.role = payload.role
    db.commit()

    # Audit log
    audit = AuditLog(
        user_id=admin_user.id,
        action="USER_ROLE_CHANGE",
        resource_type="user",
        resource_id=str(user.id),
        details={"updated_username": user.username, "new_role": user.role},
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "username": user.username, "new_role": user.role}


@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_permission(PermissionEnum.ADMIN_AUDIT)),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


@router.get("/health")
def get_system_health(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_user),
):
    # Verify DB connection
    db_ok = True
    try:
        db.execute("SELECT 1")
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "database_connected": db_ok,
        "engine": "AuthGuard Core v1.0",
        "environment": "active",
    }
