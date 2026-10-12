"""
AuthGuard Web Platform Main Application
=======================================
FastAPI application entrypoint integrating API routes, server-rendered views,
static asset serving, session authentication, and database initialization.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.api.admin import router as admin_router
from app.api.assessments import router as assessments_router
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.evidence import router as evidence_router
from app.api.findings import router as findings_router
from app.api.history import router as history_router
from app.api.reports import router as reports_router
from app.config import settings
from app.core.logging import logger
from app.core.security import hash_password
from app.dependencies import SESSION_STORE, get_current_user_optional
from app.models.base import SessionLocal, get_db, init_db
from app.models.target import Target
from app.models.user import User


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & teardown lifecycle."""
    logger.info("Initializing AuthGuard database schemas...")
    init_db()

    # Seed initial Admin user and Demo target if database is fresh
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@authguard.local",
                hashed_password=hash_password("AdminPass123!"),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            logger.info("Seeded default administrator: admin / AdminPass123!")

        demo_target = db.query(Target).filter(Target.hostname == "127.0.0.1").first()
        if not demo_target:
            demo_target = Target(
                name="AuthGuard Demo Lab Testbed",
                base_url="http://127.0.0.1:8001",
                hostname="127.0.0.1",
                approved_hostnames=["127.0.0.1", "localhost"],
                permitted_endpoints=["/login", "/verify-otp", "/api/config"],
                authorization_proof="LOCAL_TESTBED_PRE_AUTHORIZED_TOKEN",
                created_by_id=admin.id,
            )
            db.add(demo_target)
            db.commit()
            logger.info("Seeded default local demo testbed target: http://127.0.0.1:8001")
    finally:
        db.close()

    yield
    logger.info("AuthGuard web server shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AuthGuard — Website Authentication Security Assessment and Reporting Platform",
    lifespan=lifespan,
)

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files and Templates
static_dir = Path(__file__).resolve().parent / "static"
templates_dir = Path(__file__).resolve().parent / "templates"

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(templates_dir))

# Include API Routers
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(assessments_router)
app.include_router(findings_router)
app.include_router(evidence_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(admin_router)


# ---------------- Web Interface UI Routes ----------------

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(
    request: Request,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Main Web GUI Entrypoint."""
    # Auto-login to default admin session if running in local single-user mode
    if not current_user:
        admin = db.query(User).filter(User.username == "admin").first()
        if admin:
            SESSION_STORE["default_local_session"] = admin.id
            response = templates.TemplateResponse(
                "index.html",
                {"request": request, "user": admin},
            )
            response.set_cookie(
                key=settings.SESSION_COOKIE_NAME,
                value="default_local_session",
                httponly=True,
                path="/",
            )
            return response

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user},
    )


@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request):
    """Page A: Landing Page and Authentication."""
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head>
    <title>AuthGuard - Sign In</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <style>
        body { display: flex; align-items: center; justify-content: center; height: 100vh; background: #0a0e17; }
        .login-card { background: #162032; border: 1px solid #243247; border-radius: 12px; padding: 36px; width: 380px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    </style>
</head>
<body>
    <div class="login-card">
        <div style="text-align: center; margin-bottom: 24px;">
            <div class="brand-icon" style="margin: 0 auto 12px; width: 44px; height: 44px; font-size: 20px;">AG</div>
            <h2 style="color: #fff; font-size: 20px;">Sign in to AuthGuard</h2>
            <p style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Website Authentication Security Assessment</p>
        </div>
        <form onsubmit="handleLogin(event)">
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" id="username" class="form-control" value="admin" required>
            </div>
            <div class="form-group" style="margin-bottom: 24px;">
                <label class="form-label">Password</label>
                <input type="password" id="password" class="form-control" value="AdminPass123!" required>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center; padding: 12px;">Sign In</button>
        </form>
    </div>
    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById("username").value;
            const p = document.getElementById("password").value;
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: u, password: p })
            });
            if (res.ok) {
                location.href = "/";
            } else {
                alert("Invalid username or password");
            }
        }
    </script>
</body>
</html>"""
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
