"""
AuthGuard Test Suite: End-to-End Demo Lab & Assessment Pipeline Integration
===========================================================================
Tests full security audit pipeline against vulnerable and secure configurations.
"""

import pytest
from app.assessment_engine.captcha import CaptchaAssessmentSuite
from app.assessment_engine.otp import OtpAssessmentSuite
from app.assessment_engine.rate_limit import RateLimitAssessmentSuite
from app.assessment_engine.safe_client import SafeHttpClient
from app.core.safety import CircuitBreaker, RequestBudgetController
from lab.demo_auth_app.main import LAB_STATE, app as lab_app
from fastapi.testclient import TestClient

# We can wrap lab_app in a SafeHttpClient or mock transport
from starlette.testclient import TestClient as StarletteClient


class MockTransportHttpClient:
    """Adapts Starlette TestClient to SafeHttpClient interface for fast in-process tests."""

    def __init__(self, starlette_client):
        self.client = starlette_client

    async def request(self, method: str, path: str, headers=None, json_data=None, data=None):
        return self.client.request(method=method, url=path, headers=headers, json=json_data, data=data)

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_otp_vulnerable_mode_detection():
    # Set lab to vulnerable
    LAB_STATE["mode"] = "vulnerable"
    lab_client = StarletteClient(lab_app)
    mock_safe_client = MockTransportHttpClient(lab_client)

    suite = OtpAssessmentSuite(mock_safe_client, otp_endpoint="/verify-otp")
    results = await suite.run_all_checks(test_username="testuser")

    # In vulnerable mode, OTP invalid code bypass check (OTP-001) should fail and create a finding
    otp_001 = next(r for r in results if r["test_code"] == "OTP-001")
    assert otp_001["status"] == "failed"
    assert otp_001["finding"] is not None
    assert "Bypass" in otp_001["finding"]["title"]


@pytest.mark.asyncio
async def test_otp_secure_mode_defense():
    # Set lab to secure
    LAB_STATE["mode"] = "secure"
    lab_client = StarletteClient(lab_app)
    mock_safe_client = MockTransportHttpClient(lab_client)

    suite = OtpAssessmentSuite(mock_safe_client, otp_endpoint="/verify-otp")
    res = await suite.check_invalid_otp_rejection("testuser")

    # In secure mode, invalid OTP is rejected with 401, test passes!
    assert res["status"] == "passed"
    assert res["finding"] is None


@pytest.mark.asyncio
async def test_captcha_vulnerable_vs_secure():
    lab_client = StarletteClient(lab_app)
    mock_safe_client = MockTransportHttpClient(lab_client)
    suite = CaptchaAssessmentSuite(mock_safe_client, captcha_endpoint="/login")

    # Vulnerable mode: missing CAPTCHA succeeds with 200, finding created
    LAB_STATE["mode"] = "vulnerable"
    res_vuln = await suite.check_missing_captcha_token("testuser")
    assert res_vuln["status"] == "failed"
    assert res_vuln["finding"] is not None

    # Secure mode: missing CAPTCHA rejected with 400, test passes
    LAB_STATE["mode"] = "secure"
    res_sec = await suite.check_missing_captcha_token("testuser")
    assert res_sec["status"] == "passed"
    assert res_sec["finding"] is None


@pytest.mark.asyncio
async def test_rate_limit_enumeration_detection():
    lab_client = StarletteClient(lab_app)
    mock_safe_client = MockTransportHttpClient(lab_client)
    suite = RateLimitAssessmentSuite(mock_safe_client, login_endpoint="/login")

    # Vulnerable mode leaks existence: admin returns 401, nonexistent returns 404
    LAB_STATE["mode"] = "vulnerable"
    res_enum = await suite.check_account_enumeration_resistance()
    assert res_enum["status"] == "failed"
    assert res_enum["finding"] is not None
    assert "Enumeration" in res_enum["finding"]["title"]

    # Secure mode: returns uniform 401
    LAB_STATE["mode"] = "secure"
    res_sec = await suite.check_account_enumeration_resistance()
    assert res_sec["status"] == "passed"
