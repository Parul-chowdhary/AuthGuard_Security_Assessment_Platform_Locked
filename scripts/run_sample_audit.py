"""
AuthGuard Sample Audit Execution & Report Generation Script
============================================================
Runs a controlled end-to-end security assessment against the demo testbed,
populates canonical findings and evidence into the database,
and exports certified HTML, PDF, and JSON reports.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.assessment_engine.orchestrator import run_assessment_pipeline
from app.core.security import hash_password
from app.models.base import SessionLocal, init_db
from app.models.target import Target
from app.models.user import User
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.report import Report
import threading
import time
import uvicorn
from lab.demo_auth_app.main import LAB_STATE, app as lab_app


def start_lab_server():
    config = uvicorn.Config(lab_app, host="127.0.0.1", port=8001, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.2)



def run_sample_audit():
    print("[*] Initializing AuthGuard database...")
    init_db()
    db = SessionLocal()

    try:
        # 1. Ensure Admin User
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

        # 2. Register Target
        target = db.query(Target).filter(Target.name == "AuthGuard Local Demonstration Lab").first()
        if not target:
            target = Target(
                name="AuthGuard Local Demonstration Lab",
                base_url="http://127.0.0.1:8001",
                hostname="127.0.0.1",
                approved_hostnames=["127.0.0.1", "localhost"],
                permitted_endpoints=["/login", "/verify-otp"],
                authorization_proof="OFFICIAL_DEV_TESTBED_AUTHORIZATION_PROOF_TOKEN",
                created_by_id=admin.id,
            )
            db.add(target)
            db.commit()
            db.refresh(target)

        # 3. Create Assessment Record
        asm = Assessment(
            name="Quarterly Website Authentication Resilience Audit",
            target_id=target.id,
            created_by_id=admin.id,
            status="pending",
            current_phase="Queued",
            request_budget=200,
            config={
                "modules": ["otp", "rate_limit", "captcha"],
                "test_account_username": "testuser",
                "test_account_password": "TestPassword123!",
                "otp_endpoint": "/verify-otp",
                "login_endpoint": "/login",
                "captcha_endpoint": "/login",
            },
        )
        db.add(asm)
        db.commit()
        db.refresh(asm)

        print(f"[*] Created assessment #{asm.id}: '{asm.name}'")

        # 4. Set demo lab to vulnerable mode and spin up live server on port 8001
        LAB_STATE["mode"] = "vulnerable"
        print("[*] Launching local Demo Lab testbed on http://127.0.0.1:8001...")
        start_lab_server()

        # 5. Execute assessment pipeline in asyncio
        print("[*] Dispatching assessment orchestration pipeline...")
        asyncio.run(run_assessment_pipeline(asm.id, db))

        # 6. Verify Results
        db.refresh(asm)
        print(f"[+] Assessment completed with status: {asm.status.upper()}")
        print(f"    - Tests Run:     {asm.total_tests}")
        print(f"    - Passed Checks: {asm.passed_tests}")
        print(f"    - Failed Checks: {asm.failed_tests}")
        print(f"    - Requests Used: {asm.requests_used} / {asm.request_budget}")

        findings = db.query(Finding).filter(Finding.assessment_id == asm.id).all()
        print(f"\n[+] Identified Findings ({len(findings)}):")
        for f in findings:
            print(f"    • [{f.severity.upper()}] {f.title} (CVSS {f.cvss_score}) -> {f.affected_endpoint}")

        reports = db.query(Report).filter(Report.assessment_id == asm.id).all()
        print(f"\n[+] Generated Report Artifacts ({len(reports)}):")
        for r in reports:
            p = Path(r.file_path)
            size = p.stat().st_size if p.exists() else 0
            print(f"    • [{r.report_format.upper()}] {r.filename} ({size:,} bytes, SHA256: {r.file_hash[:16]}...)")

    finally:
        db.close()


if __name__ == "__main__":
    run_sample_audit()
