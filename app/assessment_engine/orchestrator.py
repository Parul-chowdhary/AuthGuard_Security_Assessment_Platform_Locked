"""
AuthGuard Assessment Orchestration Engine
=========================================
Coordinates end-to-end execution of authentication assessments, managing
task lifecycles, progress updates, safe dispatching, and evidence persistence.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.assessment_engine.captcha import CaptchaAssessmentSuite
from app.assessment_engine.otp import OtpAssessmentSuite
from app.assessment_engine.rate_limit import RateLimitAssessmentSuite
from app.assessment_engine.safe_client import SafeHttpClient
from app.core.logging import logger
from app.core.safety import CircuitBreaker, RequestBudgetController
from app.core.scope import validate_target_url
from app.models.assessment import Assessment, TestCase
from app.models.evidence import EvidenceRecord
from app.models.finding import Finding
from app.models.target import Target

# Global cancellation registry (assessment_id -> boolean)
CANCELLED_ASSESSMENTS: set[int] = set()


def request_assessment_cancellation(assessment_id: int) -> None:
    """Flag an assessment for immediate cancellation."""
    CANCELLED_ASSESSMENTS.add(assessment_id)


def is_cancellation_requested(assessment_id: int) -> bool:
    return assessment_id in CANCELLED_ASSESSMENTS


async def run_assessment_pipeline(assessment_id: int, db: Session) -> None:
    """Execute the full assessment test pipeline in an asynchronous worker."""
    assessment: Optional[Assessment] = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        logger.error(f"Cannot run assessment: ID {assessment_id} not found.")
        return

    target: Target = assessment.target
    config: Dict = assessment.config or {}

    try:
        # 1. State: Running
        assessment.status = "running"
        assessment.current_phase = "Validating target availability & scope"
        assessment.started_at = datetime.now(timezone.utc)
        db.commit()

        # 2. Scope & SSRF verification
        norm_url, hostname, ips = validate_target_url(
            target.base_url,
            approved_hostnames=target.approved_hostnames or [target.hostname],
            allow_local_for_testing=True,
        )

        budget_ctrl = RequestBudgetController(
            budget=assessment.request_budget,
            max_budget=1000,
        )
        circuit_breaker = CircuitBreaker(failure_threshold=4)

        client = SafeHttpClient(
            base_url=target.base_url,
            approved_hostnames=target.approved_hostnames or [target.hostname],
            budget_controller=budget_ctrl,
            circuit_breaker=circuit_breaker,
            allow_local_for_testing=True,
        )

        selected_modules = config.get("modules", ["otp", "rate_limit", "captcha"])
        test_user = config.get("test_account_username", "testuser")
        otp_endpoint = config.get("otp_endpoint", "/verify-otp")
        login_endpoint = config.get("login_endpoint", "/login")
        captcha_endpoint = config.get("captcha_endpoint", "/login")

        all_test_results: List[Dict] = []

        # 3. Module Execution
        for mod in selected_modules:
            if is_cancellation_requested(assessment_id):
                assessment.status = "cancelled"
                assessment.current_phase = "Cancelled by user"
                assessment.completed_at = datetime.now(timezone.utc)
                db.commit()
                await client.close()
                return

            if mod == "otp":
                assessment.current_phase = "Executing OTP security checks"
                db.commit()
                otp_suite = OtpAssessmentSuite(client, otp_endpoint=otp_endpoint)
                results = await otp_suite.run_all_checks(test_username=test_user)
                all_test_results.extend(results)

            elif mod == "rate_limit":
                assessment.current_phase = "Executing login rate-limiting checks"
                db.commit()
                rl_suite = RateLimitAssessmentSuite(client, login_endpoint=login_endpoint)
                results = await rl_suite.run_all_checks(test_username=test_user)
                all_test_results.extend(results)

            elif mod == "captcha":
                assessment.current_phase = "Executing CAPTCHA validation checks"
                db.commit()
                cap_suite = CaptchaAssessmentSuite(client, captcha_endpoint=captcha_endpoint)
                results = await cap_suite.run_all_checks(test_username=test_user)
                all_test_results.extend(results)

        await client.close()

        # 4. Record Results, Findings, and Evidence
        assessment.current_phase = "Processing findings and evidence"
        assessment.total_tests = len(all_test_results)
        assessment.completed_tests = len(all_test_results)
        assessment.requests_used = budget_ctrl.requests_sent

        passed_count = 0
        failed_count = 0

        for item in all_test_results:
            status = item["status"]
            if status == "passed":
                passed_count += 1
            else:
                failed_count += 1

            tc = TestCase(
                assessment_id=assessment.id,
                module=item["module"],
                test_code=item["test_code"],
                name=item["name"],
                status=status,
                details=item.get("details", ""),
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            db.add(tc)
            db.flush()

            # Create finding if security weakness identified
            finding_data = item.get("finding")
            finding_obj = None
            if finding_data:
                finding_obj = Finding(
                    assessment_id=assessment.id,
                    test_case_id=tc.id,
                    title=finding_data["title"],
                    description=finding_data["description"],
                    module=item["module"],
                    affected_endpoint=item["evidence"]["endpoint"],
                    severity=finding_data["severity"],
                    cvss_score=finding_data.get("cvss_score", 5.0),
                    confidence=finding_data.get("confidence", "Confirmed"),
                    validation_status=finding_data.get("validation_status", "Confirmed"),
                    expected_behavior=finding_data["expected_behavior"],
                    actual_behavior=finding_data["actual_behavior"],
                    potential_impact=finding_data["potential_impact"],
                    remediation=finding_data["remediation"],
                )
                db.add(finding_obj)
                db.flush()

            # Record sanitized evidence
            ev_data = item.get("evidence")
            if ev_data:
                ev_record = EvidenceRecord(
                    assessment_id=assessment.id,
                    finding_id=finding_obj.id if finding_obj else None,
                    test_case_id=tc.id,
                    endpoint=ev_data["endpoint"],
                    http_method=ev_data["method"],
                    sanitized_request_body=ev_data.get("req_body", ""),
                    sanitized_response_status=ev_data["resp_status"],
                    sanitized_response_headers=ev_data.get("resp_headers", {}),
                    sanitized_response_body=ev_data.get("resp_body", ""),
                    integrity_hash=ev_data.get("hash", ""),
                )
                db.add(ev_record)

        assessment.passed_tests = passed_count
        assessment.failed_tests = failed_count
        assessment.status = "completed"
        assessment.current_phase = "Assessment finished successfully"
        assessment.completed_at = datetime.now(timezone.utc)
        db.commit()

        # Trigger automatic report generation
        from app.reporting.generator import generate_all_reports
        generate_all_reports(assessment_id, db)

    except Exception as e:
        logger.exception(f"Assessment {assessment_id} failed with error: {e}")
        assessment.status = "failed"
        assessment.current_phase = f"Failed: {str(e)[:150]}"
        assessment.error_message = str(e)
        assessment.completed_at = datetime.now(timezone.utc)
        db.commit()
