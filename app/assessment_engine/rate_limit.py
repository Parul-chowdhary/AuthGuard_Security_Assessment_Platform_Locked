"""
AuthGuard Brute-Force & Rate-Limiting Assessment Module
======================================================
Evaluates login rate limiting, HTTP 429 adherence, progressive delays,
and account enumeration resistance using strictly bounded request budgets.
"""

import time
from typing import Any, Dict, List
from app.assessment_engine.safe_client import SafeHttpClient
from app.core.logging import logger
from app.evidence.redaction import (
    compute_evidence_integrity_hash,
    sanitize_body_content,
    sanitize_headers,
)
from app.risk.scoring import calculate_cvss_score


class RateLimitAssessmentSuite:
    """Bounded, ethical rate-limiting and brute-force resistance testing."""

    def __init__(self, client: SafeHttpClient, login_endpoint: str = "/login"):
        self.client = client
        self.login_endpoint = login_endpoint

    async def run_all_checks(
        self,
        test_username: str = "testuser",
    ) -> List[Dict[str, Any]]:
        results = []

        # 1. Bounded rapid login burst (tests rate-limiting headers & 429)
        res1 = await self.check_login_rate_limiting(test_username)
        results.append(res1)

        # 2. Account enumeration resistance check
        res2 = await self.check_account_enumeration_resistance()
        results.append(res2)

        return results

    async def check_login_rate_limiting(self, username: str) -> Dict[str, Any]:
        """Send a bounded burst of 6 invalid logins to detect rate-limiting / lockout defenses."""
        responses = []
        has_rate_limit_header = False
        rate_limited = False

        for i in range(6):
            payload = {"username": username, "password": f"InvalidPassword_Attempt_{i}"}
            t0 = time.time()
            resp = await self.client.request("POST", self.login_endpoint, json_data=payload)
            elapsed = time.time() - t0

            headers = {k.lower(): v for k, v in resp.headers.items()}
            if any(h in headers for h in ("retry-after", "x-ratelimit-remaining", "ratelimit-remaining")):
                has_rate_limit_header = True

            responses.append({"status": resp.status_code, "elapsed": round(elapsed, 3)})

            if resp.status_code in (429, 423):
                rate_limited = True
                break  # Stop immediately upon defensive trigger

        passed = rate_limited or has_rate_limit_header
        finding = None

        if not passed:
            cvss, severity = calculate_cvss_score(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                confidentiality="L", integrity="L"
            )
            finding = {
                "title": "Missing Rate Limiting on Authentication Endpoint",
                "description": (
                    f"Authentication endpoint '{self.login_endpoint}' processed repeated invalid logins "
                    "without returning HTTP 429 (Too Many Requests), rate-limit headers, or progressive backoff."
                ),
                "severity": "Medium",
                "cvss_score": 5.3,
                "confidence": "Confirmed",
                "validation_status": "Confirmed",
                "expected_behavior": "Server should return HTTP 429 or enforce temporary lockout after 5 failed login attempts.",
                "actual_behavior": f"Endpoint returned standard rejection statuses without rate limiting: {[r['status'] for r in responses]}",
                "potential_impact": "Enables automated offline/online credential testing and password guessing attacks.",
                "remediation": "Implement IP and username based rate limiting (e.g., token bucket or leaky bucket algorithm) returning HTTP 429.",
            }

        last_resp = responses[-1]
        ev_hash = compute_evidence_integrity_hash(
            self.login_endpoint, "POST", "Bounded login burst test", last_resp["status"], str(responses)
        )

        return {
            "test_code": "RL-001",
            "name": "Login Rate Limiting & HTTP 429 Defense",
            "module": "rate_limit",
            "status": "passed" if passed else "failed",
            "details": f"Responses: {[r['status'] for r in responses]}, Rate-limited: {rate_limited}",
            "finding": finding,
            "evidence": {
                "endpoint": self.login_endpoint,
                "method": "POST",
                "req_body": f"Bounded 6-attempt burst for user '{username}'",
                "resp_status": last_resp["status"],
                "resp_headers": {},
                "resp_body": f"Execution telemetry: {responses}",
                "hash": ev_hash,
            },
        }

    async def check_account_enumeration_resistance(self) -> Dict[str, Any]:
        """
        Verify whether the server discloses user existence through divergent error messages
        between an existing username and a nonexistent random username.
        """
        # Attempt with standard existing user
        payload_existing = {"username": "admin", "password": "WrongPassword123!"}
        resp1 = await self.client.request("POST", self.login_endpoint, json_data=payload_existing)

        # Attempt with random nonexistent user
        payload_nonexistent = {"username": "nonexistent_usr_98741", "password": "WrongPassword123!"}
        resp2 = await self.client.request("POST", self.login_endpoint, json_data=payload_nonexistent)

        # Compare error messages
        body1 = resp1.text.lower()
        body2 = resp2.text.lower()

        leak_hints = ["user not found", "username does not exist", "invalid user", "no such account"]
        leaks_existence = any(hint in body2 for hint in leak_hints) and not any(hint in body1 for hint in leak_hints)
        distinct_status = resp1.status_code != resp2.status_code

        finding = None
        has_finding = leaks_existence or distinct_status
        passed = not has_finding

        if has_finding:
            cvss, severity = calculate_cvss_score(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                confidentiality="L", integrity="N", availability="N"
            )
            finding = {
                "title": "Authentication Account Enumeration Weakness",
                "description": (
                    "The authentication endpoint returns distinguishable error messages or status codes "
                    "for valid usernames versus invalid usernames, allowing adversaries to enumerate valid accounts."
                ),
                "severity": "Low",
                "cvss_score": 3.7,
                "confidence": "Suspected",
                "validation_status": "Suspected",
                "expected_behavior": "Server must return uniform error messages (e.g., 'Invalid credentials') and identical HTTP status codes.",
                "actual_behavior": f"Existing user status: {resp1.status_code}, Nonexistent user status: {resp2.status_code}",
                "potential_impact": "Allows attackers to harvest valid corporate usernames for targeted spear-phishing or credential attacks.",
                "remediation": "Normalize all authentication failure messages and response times to be indistinguishable.",
            }

        return {
            "test_code": "RL-002",
            "name": "Account Enumeration Resistance",
            "module": "rate_limit",
            "status": "passed" if passed else "failed",
            "details": f"Status 1: {resp1.status_code}, Status 2: {resp2.status_code}",
            "finding": finding,
            "evidence": {
                "endpoint": self.login_endpoint,
                "method": "POST",
                "req_body": "Comparison probes with valid vs invalid username",
                "resp_status": resp2.status_code,
                "resp_headers": {},
                "resp_body": f"Valid user resp: {resp1.text[:200]} | Invalid user resp: {resp2.text[:200]}",
                "hash": compute_evidence_integrity_hash(self.login_endpoint, "POST", "", resp2.status_code, resp2.text),
            },
        }
