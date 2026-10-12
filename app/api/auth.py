"""
AuthGuard Authentication API Endpoints
======================================
User registration, credential login, session issuance, and logout.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import generate_session_id, hash_password, verify_password
from app.dependencies import SESSION_STORE, get_current_user
from app.models.base import get_db
from app.models.report import AuditLog
from app.models.user import User
from app.schemas.auth import UserLoginSchema, UserRegisterSchema, UserResponseSchema

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponseSchema)
def register_user(payload: UserRegisterSchema, db: Session = Depends(get_db)):
    # Check if username or email exists
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered.",
        )

    # First user registered automatically receives 'admin' role
    user_count = db.query(User).count()
    role = "admin" if user_count == 0 else (payload.role or "auditor")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Audit log
    audit = AuditLog(
        user_id=user.id,
        action="USER_REGISTER",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username, "role": user.role},
    )
    db.add(audit)
    db.commit()

    return user


@router.post("/login")
def login_user(payload: UserLoginSchema, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username, User.is_active == True).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Issue high-entropy session ID
    session_id = generate_session_id()
    SESSION_STORE[session_id] = user.id

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=settings.SESSION_SECURE_COOKIE,
        samesite=settings.SESSION_SAME_SITE,
        path="/",
    )

    # Audit log
    audit = AuditLog(
        user_id=user.id,
        action="USER_LOGIN",
        resource_type="user",
        resource_id=str(user.id),
    )
    db.add(audit)
    db.commit()

    return {
        "status": "success",
        "message": "Authenticated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.post("/logout")
def logout_user(request: Request, response: Response, current_user: User = Depends(get_current_user)):
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_id and session_id in SESSION_STORE:
        del SESSION_STORE[session_id]

    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/me", response_model=UserResponseSchema)
def get_authenticated_user_profile(current_user: User = Depends(get_current_user)):
    return current_user
