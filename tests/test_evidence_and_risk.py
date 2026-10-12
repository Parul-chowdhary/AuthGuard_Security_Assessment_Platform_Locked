"""
AuthGuard Test Suite: Evidence Redaction & CVSS Risk Scoring
============================================================
"""

from app.evidence.redaction import (
    compute_evidence_integrity_hash,
    sanitize_body_content,
    sanitize_headers,
)
from app.risk.scoring import calculate_cvss_score


def test_sanitize_headers():
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer super-secret-jwt-token-12345",
        "Cookie": "sessionid=xyz987; token=secretval",
        "User-Agent": "TestClient/1.0",
    }
    sanitized = sanitize_headers(headers)

    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Authorization"] == "[REDACTED_SENSITIVE_HEADER]"
    assert sanitized["Cookie"] == "[REDACTED_SENSITIVE_HEADER]"
    assert sanitized["User-Agent"] == "TestClient/1.0"


def test_sanitize_body_json():
    raw_body = '{"username": "admin", "password": "PlainTextPassword123!", "otp": "999888"}'
    sanitized = sanitize_body_content(raw_body)

    assert "PlainTextPassword123!" not in sanitized
    assert "999888" not in sanitized
    assert "[REDACTED]" in sanitized


def test_evidence_integrity_hash():
    h1 = compute_evidence_integrity_hash("/login", "POST", "body1", 200, "resp1")
    h2 = compute_evidence_integrity_hash("/login", "POST", "body1", 200, "resp1")
    h3 = compute_evidence_integrity_hash("/login", "POST", "diff_body", 200, "resp1")

    assert len(h1) == 64
    assert h1 == h2
    assert h1 != h3


def test_cvss_scoring_tiers():
    # High impact vulnerability
    score_crit, sev_crit = calculate_cvss_score(confidentiality="H", integrity="H")
    assert score_crit >= 7.0
    assert sev_crit in ("High", "Critical")

    # Low impact with high complexity
    score_low, sev_low = calculate_cvss_score(
        attack_complexity="H",
        confidentiality="L",
        integrity="N",
        availability="N",
    )
    assert score_low <= 4.0
    assert sev_low in ("Low", "Medium")
