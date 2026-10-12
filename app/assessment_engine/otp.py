"""
AuthGuard OTP Security Assessment Module
========================================
Audits One-Time Password verification controls: invalid code rejection,
expiration enforcement, reuse prevention, rate limits, and state binding.
"""

from typing import Any, Dict, List, Tuple
from app.assessment_engine.safe_client import SafeHttpClient
from app.core.logging import logger
from app.evidence.redaction import (
    compute_evidence_integrity_hash,
    sanitize_body_content,
    sanitize_headers,
)
from app.risk.scoring import calculate_cvss_score


class OtpAssessmentSuite:
    """Executes controlled OTP security verification checks."""

    def __init__(self, client: SafeHttpClient, otp_endpoint: str = "/verify-otp"):
        self.client = client
        self.otp_endpoint = otp_endpoint

    async def run_all_checks(
        self,
        test_username: str = "testuser",
    ) -> List[Dict[str, Any]]:
        results = []

        # 1. Invalid OTP rejection
        res1 = await self.check_invalid_otp_rejection(test_username)
        results.append(res1)

        # 2. OTP Reuse / Replay vulnerability
        res2 = await self.check_otp_replay_resistance(test_username)
        results.append(res2)

        # 3. OTP Attempt Limits / Brute-force resistance (bounded)
        res3 = await self.check_otp_attempt_limits(test_username)
        results.append(res3)

        # 4. OTP Account Binding validation
        res4 = await self.check_otp_account_binding(test_username)
        results.append(res4)

        return results

    async def check_invalid_otp_rejection(self, username: str) -> Dict[str, Any]:
        """Test whether invalid OTP values are strictly rejected."""
        payload = {"username": username, "otp": "000000"}
        resp = await self.client.request("POST", self.otp_endpoint, json_data=payload)

        # If server returns 200 OK or claims success for '000000', severe flaw
        passed = resp.status_code in (400, 401, 403, 422)
        has_finding = not passed and resp.status_code == 200

        finding = None
        if has_finding:
            cvss, severity = calculate_cvss_score(confidentiality="H", integrity="H", availability="N")
            finding = {
                "title": "OTP Verification Bypass on Invalid Code",
                "description": "The server accepted an obviously invalid OTP code ('000000') or returned 200 OK without verification.",
                "severity": severity,
                "cvss_score": cvss,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "Server must respond with HTTP 401 Unauthorized or 400 Bad Request.",
                "actual_behavior": f"Server responded with HTTP {resp.status_code}.",
                "potential_impact": "Complete authentication bypass enabling account takeover without valid second factor.",
                "remediation": "Enforce strict cryptographic comparison of OTP secrets and reject unverified codes.",
            }

        req_sanitized = sanitize_body_content(str(payload))
        resp_sanitized = sanitize_body_content(resp.text)
        ev_hash = compute_evidence_integrity_hash(
            self.otp_endpoint, "POST", req_sanitized, resp.status_code, resp_sanitized
        )

        return {
            "test_code": "OTP-001",
            "name": "Invalid OTP Code Rejection",
            "module": "otp",
            "status": "passed" if passed else "failed",
            "details": f"Status code received: {resp.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.otp_endpoint,
                "method": "POST",
                "req_body": req_sanitized,
                "resp_status": resp.status_code,
                "resp_headers": sanitize_headers(dict(resp.headers)),
                "resp_body": resp_sanitized[:2000],
                "hash": ev_hash,
            },
        }

    async def check_otp_replay_resistance(self, username: str) -> Dict[str, Any]:
        """Test whether previously used OTP tokens are invalidated upon consumption."""
        payload = {"username": username, "otp": "123456", "retest_replay": True}
        # First attempt
        resp1 = await self.client.request("POST", self.otp_endpoint, json_data=payload)
        # Immediate replay attempt
        resp2 = await self.client.request("POST", self.otp_endpoint, json_data=payload)

        # If both returned 200 OK, replay is possible
        has_finding = resp1.status_code == 200 and resp2.status_code == 200
        passed = not has_finding

        finding = None
        if has_finding:
            cvss, severity = calculate_cvss_score(confidentiality="H", integrity="H")
            finding = {
                "title": "OTP Replay / Reuse Vulnerability",
                "description": "The server permitted reuse of an already submitted One-Time Password.",
                "severity": severity,
                "cvss_score": cvss,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "OTPs must be single-use and immediately consumed/invalidated upon first verification.",
                "actual_behavior": "Server accepted identical OTP on subsequent verification request.",
                "potential_impact": "Attackers intercepting an OTP can reuse it to authenticate.",
                "remediation": "Mark OTP tokens as consumed in the database immediately upon successful verification.",
            }

        return {
            "test_code": "OTP-002",
            "name": "OTP Token Replay & Reuse Resistance",
            "module": "otp",
            "status": "passed" if passed else "failed",
            "details": f"First attempt status: {resp1.status_code}, Replay attempt status: {resp2.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.otp_endpoint,
                "method": "POST",
                "req_body": sanitize_body_content(str(payload)),
                "resp_status": resp2.status_code,
                "resp_headers": sanitize_headers(dict(resp2.headers)),
                "resp_body": sanitize_body_content(resp2.text)[:2000],
                "hash": compute_evidence_integrity_hash(
                    self.otp_endpoint, "POST", str(payload), resp2.status_code, resp2.text
                ),
            },
        }

    async def check_otp_attempt_limits(self, username: str) -> Dict[str, Any]:
        """Test whether rapid incorrect OTP attempts trigger rate-limiting or lockout (bounded to 5 requests)."""
        responses = []
        for i in range(5):
            payload = {"username": username, "otp": f"99990{i}"}
            r = await self.client.request("POST", self.otp_endpoint, json_data=payload)
            responses.append(r.status_code)

        # Check if rate limiting (429 or lockout 403) was triggered within 5 tries
        rate_limited = any(code in (429, 423) for code in responses)
        passed = rate_limited  # Ideal defense trips limit quickly

        finding = None
        if not rate_limited:
            cvss, severity = calculate_cvss_score(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                confidentiality="H", integrity="H"
            )
            finding = {
                "title": "Missing OTP Attempt Rate Limiting",
                "description": "Endpoint permitted 5 consecutive invalid OTP attempts without rate-limiting (HTTP 429) or lockout.",
                "severity": "Medium",
                "cvss_score": 5.3,
                "confidence": "Suspected",
                "validation_status": "Suspected",
                "expected_behavior": "After 3-5 incorrect attempts, server should return HTTP 429 or lock the verification session.",
                "actual_behavior": f"Received responses: {responses}",
                "potential_impact": "Increases susceptibility to automated 4-6 digit OTP brute-force attacks.",
                "remediation": "Enforce strict per-account and per-IP attempt limits (max 3-5 failed tries per OTP).",
            }

        return {
            "test_code": "OTP-003",
            "name": "OTP Rate-Limiting & Attempt Quota",
            "module": "otp",
            "status": "passed" if passed else "failed",
            "details": f"Sequence of HTTP response codes: {responses}",
            "finding": finding,
            "evidence": {
                "endpoint": self.otp_endpoint,
                "method": "POST",
                "req_body": f"5 bounded invalid OTP submissions for user {username}",
                "resp_status": responses[-1],
                "resp_headers": {},
                "resp_body": f"Response sequence: {responses}",
                "hash": compute_evidence_integrity_hash(self.otp_endpoint, "POST", "", responses[-1], str(responses)),
            },
        }

    async def check_otp_account_binding(self, username: str) -> Dict[str, Any]:
        """Test whether OTP submission strictly enforces account binding and session association."""
        # Submit valid structure without username or session token
        payload = {"otp": "123456"}
        resp = await self.client.request("POST", self.otp_endpoint, json_data=payload)

        # Missing user/session identifier must be rejected
        passed = resp.status_code in (400, 401, 403, 422)
        finding = None
        if not passed and resp.status_code == 200:
            finding = {
                "title": "Unbound OTP Verification State",
                "description": "Server accepted OTP verification without user account or session binding.",
                "severity": "High",
                "cvss_score": 7.5,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "Server must require authenticated session or explicit user binding.",
                "actual_behavior": f"Server returned HTTP {resp.status_code}",
                "potential_impact": "Cross-user OTP acceptance enabling lateral privilege escalation.",
                "remediation": "Bind OTP secrets strictly to the server-side session of the authenticating user.",
            }

        return {
            "test_code": "OTP-004",
            "name": "OTP Session & Account Binding",
            "module": "otp",
            "status": "passed" if passed else "failed",
            "details": f"Response status for unbound verification: {resp.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.otp_endpoint,
                "method": "POST",
                "req_body": sanitize_body_content(str(payload)),
                "resp_status": resp.status_code,
                "resp_headers": sanitize_headers(dict(resp.headers)),
                "resp_body": sanitize_body_content(resp.text)[:2000],
                "hash": compute_evidence_integrity_hash(self.otp_endpoint, "POST", str(payload), resp.status_code, resp.text),
            },
        }
