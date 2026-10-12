"""
AuthGuard CAPTCHA Server Enforcement Assessment Module
======================================================
Tests server-side CAPTCHA enforcement: missing tokens, invalid tokens,
token reuse, and fail-closed validation behavior.
"""

from typing import Any, Dict, List
from app.assessment_engine.safe_client import SafeHttpClient
from app.core.logging import logger
from app.evidence.redaction import (
    compute_evidence_integrity_hash,
    sanitize_body_content,
    sanitize_headers,
)
from app.risk.scoring import calculate_cvss_score


class CaptchaAssessmentSuite:
    """Evaluates whether authentication forms enforce CAPTCHA on the backend."""

    def __init__(self, client: SafeHttpClient, captcha_endpoint: str = "/login"):
        self.client = client
        self.captcha_endpoint = captcha_endpoint

    async def run_all_checks(
        self,
        test_username: str = "testuser",
    ) -> List[Dict[str, Any]]:
        results = []

        # 1. Missing CAPTCHA token check
        res1 = await self.check_missing_captcha_token(test_username)
        results.append(res1)

        # 2. Invalid / forged CAPTCHA token check
        res2 = await self.check_invalid_captcha_token(test_username)
        results.append(res2)

        # 3. CAPTCHA token reuse / replay check
        res3 = await self.check_captcha_token_reuse(test_username)
        results.append(res3)

        return results

    async def check_missing_captcha_token(self, username: str) -> Dict[str, Any]:
        """Submit authentication request with no CAPTCHA response field."""
        payload = {"username": username, "password": "TestPassword123!"}  # no captcha_token
        resp = await self.client.request("POST", self.captcha_endpoint, json_data=payload)

        # If endpoint is advertised as CAPTCHA-protected, omitting the token should return 400 or 422
        # If it returns 200 (or processes authentication directly), CAPTCHA is not enforced server-side
        has_finding = resp.status_code == 200
        passed = resp.status_code in (400, 422, 403)

        finding = None
        if has_finding:
            cvss, severity = calculate_cvss_score(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                confidentiality="M" if hasattr(self, "M") else "H", integrity="H"
            )
            finding = {
                "title": "Missing Server-Side CAPTCHA Enforcement",
                "description": (
                    f"Authentication endpoint '{self.captcha_endpoint}' accepted an authentication request "
                    "without requiring a CAPTCHA response token."
                ),
                "severity": "Medium",
                "cvss_score": 6.5,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "Server must validate that a valid CAPTCHA token accompanies the request and reject submissions missing the token with HTTP 400 or 422.",
                "actual_behavior": f"Server processed request without CAPTCHA token and returned HTTP {resp.status_code}.",
                "potential_impact": "Enables automated bot attacks, credential stuffing, and scripted login workflows.",
                "remediation": "Enforce mandatory server-side verification of CAPTCHA tokens with the provider before processing credentials.",
            }

        return {
            "test_code": "CAP-001",
            "name": "Missing CAPTCHA Token Rejection",
            "module": "captcha",
            "status": "passed" if passed else "failed",
            "details": f"Server status code for omitted token: {resp.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.captcha_endpoint,
                "method": "POST",
                "req_body": sanitize_body_content(str(payload)),
                "resp_status": resp.status_code,
                "resp_headers": sanitize_headers(dict(resp.headers)),
                "resp_body": sanitize_body_content(resp.text)[:2000],
                "hash": compute_evidence_integrity_hash(self.captcha_endpoint, "POST", str(payload), resp.status_code, resp.text),
            },
        }

    async def check_invalid_captcha_token(self, username: str) -> Dict[str, Any]:
        """Submit an explicitly forged/garbage CAPTCHA token."""
        payload = {
            "username": username,
            "password": "TestPassword123!",
            "captcha_token": "FORGED_INVALID_TOKEN_99999999999",
        }
        resp = await self.client.request("POST", self.captcha_endpoint, json_data=payload)

        # Server must reject forged token
        passed = resp.status_code in (400, 401, 403, 422)
        finding = None

        if not passed and resp.status_code == 200:
            finding = {
                "title": "Forged CAPTCHA Token Accepted",
                "description": "Server accepted a fabricated CAPTCHA token without validating its signature with the CAPTCHA verification API.",
                "severity": "High",
                "cvss_score": 7.5,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "Server must query verification provider and reject unauthorized/forged tokens.",
                "actual_behavior": f"Server accepted forged token and returned HTTP {resp.status_code}.",
                "potential_impact": "Completely negates anti-bot protections by permitting static dummy tokens.",
                "remediation": "Validate every token server-side via the provider secret key and verify success: true.",
            }

        return {
            "test_code": "CAP-002",
            "name": "Forged / Invalid CAPTCHA Token Rejection",
            "module": "captcha",
            "status": "passed" if passed else "failed",
            "details": f"Status for forged token: {resp.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.captcha_endpoint,
                "method": "POST",
                "req_body": sanitize_body_content(str(payload)),
                "resp_status": resp.status_code,
                "resp_headers": sanitize_headers(dict(resp.headers)),
                "resp_body": sanitize_body_content(resp.text)[:2000],
                "hash": compute_evidence_integrity_hash(self.captcha_endpoint, "POST", str(payload), resp.status_code, resp.text),
            },
        }

    async def check_captcha_token_reuse(self, username: str) -> Dict[str, Any]:
        """Submit the same validly structured token twice to test replay resistance."""
        token = "test_valid_single_use_token_12345"
        payload = {"username": username, "password": "TestPassword123!", "captcha_token": token}

        # Attempt 1
        resp1 = await self.client.request("POST", self.captcha_endpoint, json_data=payload)
        # Attempt 2
        resp2 = await self.client.request("POST", self.captcha_endpoint, json_data=payload)

        # If both attempts returned 200 OK, token replay is unmitigated
        has_finding = resp1.status_code == 200 and resp2.status_code == 200
        passed = not has_finding
        finding = None

        if has_finding:
            finding = {
                "title": "CAPTCHA Token Replay / Reuse Vulnerability",
                "description": "The server permitted reuse of an already submitted CAPTCHA token across multiple requests.",
                "severity": "Medium",
                "cvss_score": 5.8,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "CAPTCHA tokens must be strictly single-use and rejected on subsequent attempts.",
                "actual_behavior": "Server accepted previously submitted CAPTCHA token on re-use attempt.",
                "potential_impact": "Attackers can solve a single CAPTCHA and replay the token to automate multiple requests.",
                "remediation": "Ensure CAPTCHA tokens are consumed or enforce provider timestamp and hostname validation.",
            }

        return {
            "test_code": "CAP-003",
            "name": "CAPTCHA Token Replay Resistance",
            "module": "captcha",
            "status": "passed" if passed else "failed",
            "details": f"Attempt 1 status: {resp1.status_code}, Attempt 2 status: {resp2.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.captcha_endpoint,
                "method": "POST",
                "req_body": sanitize_body_content(str(payload)),
                "resp_status": resp2.status_code,
                "resp_headers": sanitize_headers(dict(resp2.headers)),
                "resp_body": sanitize_body_content(resp2.text)[:2000],
                "hash": compute_evidence_integrity_hash(self.captcha_endpoint, "POST", str(payload), resp2.status_code, resp2.text),
            },
        }
