"""
AuthGuard FastAPI Dependencies
==============================
Handles database session injection, session cookie authentication,
and server-side role/permission authorization enforcement.
"""

from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.permissions import PermissionEnum, user_has_permission
from app.models.base import get_db
from app.models.user import User


# In-memory session store (session_id -> user_id)
# For persistence across reboots, this can be backed by database sessions table or redis.
SESSION_STORE: dict[str, int] = {}


def get_current_user_optional(
    request: Request,
    authguard_session: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Retrieve authenticated user if valid session exists; otherwise return None."""
    session_id = authguard_session or request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_id or session_id not in SESSION_STORE:
        return None

    user_id = SESSION_STORE[session_id]
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    return user


def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional),
) -> User:
    """Enforce authentication on protected API endpoints. Raises 401 if unauthenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Cookie"},
        )
    return user


def require_permission(permission: PermissionEnum):
    """Enforce role-based permission checks at the route handler level."""
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not user_has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Missing required permission '{permission.value}'.",
            )
        return current_user
    return permission_checker
