"""
AuthGuard Sensitive Data Redaction & Evidence Sanitizer
=======================================================
Redacts credentials, OTP codes, session tokens, and cryptographic keys
from HTTP request and response payloads before storage and reporting.
"""

import hashlib
import json
import re
from typing import Any, Dict, Optional, Tuple

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
}

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "otp",
    "code",
    "pin",
    "session_id",
    "auth_token",
    "client_secret",
}


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a sanitized copy of headers with secrets redacted."""
    sanitized = {}
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key in SENSITIVE_HEADER_KEYS:
            sanitized[key] = "[REDACTED_SENSITIVE_HEADER]"
        else:
            sanitized[key] = value
    return sanitized


def sanitize_json_object(obj: Any) -> Any:
    """Recursively scrub sensitive keys in JSON structures."""
    if isinstance(obj, dict):
        scrubbed = {}
        for k, v in obj.items():
            if any(s in str(k).lower() for s in SENSITIVE_FIELD_NAMES):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = sanitize_json_object(v)
        return scrubbed
    elif isinstance(obj, list):
        return [sanitize_json_object(item) for item in obj]
    return obj


def sanitize_body_content(body: Optional[str]) -> str:
    """Sanitize body string, parsing JSON or using regex heuristics if plain text/form."""
    if not body:
        return ""

    body_trimmed = body.strip()
    if (body_trimmed.startswith("{") and body_trimmed.endswith("}")) or (
        body_trimmed.startswith("[") and body_trimmed.endswith("]")
    ):
        try:
            parsed = json.loads(body_trimmed)
            sanitized_parsed = sanitize_json_object(parsed)
            return json.dumps(sanitized_parsed, indent=2)
        except Exception:
            pass

    # Regex heuristic for URL-encoded or raw form data
    redacted = body
    for field_name in SENSITIVE_FIELD_NAMES:
        pattern = re.compile(rf"({field_name}=)([^&\s]+)", re.IGNORECASE)
        redacted = pattern.sub(r"\1[REDACTED]", redacted)

    return redacted


def compute_evidence_integrity_hash(
    endpoint: str,
    method: str,
    req_body: str,
    resp_status: int,
    resp_body: str,
) -> str:
    """Compute SHA-256 integrity hash for sanitized evidence record."""
    raw = f"{method}|{endpoint}|{req_body}|{resp_status}|{resp_body}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
