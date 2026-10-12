"""
AuthGuard Core Logging & Sensitive Data Redaction
=================================================
Structured logging configuration with automated secret sanitization in logs.
"""

import logging
import re
import sys
from typing import Any, Dict

# Regex patterns for redacting secrets in log records
SENSITIVE_PATTERNS = [
    (re.compile(r'(password|passwd|pwd|secret|apiKey|api_key|token|auth_token|otp|code)=([^\s&"\'<>]+)', re.IGNORECASE), r'\1=[REDACTED]'),
    (re.compile(r'("?(?:password|token|secret|otp|authorization|access_token|refresh_token)"?\s*:\s*")([^"]+)(")', re.IGNORECASE), r'\1[REDACTED]\3'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9_\-\.]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Basic\s+)[A-Za-z0-9+/=]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(sessionid|connect\.sid|authguard_session)=([^\s;&]+)', re.IGNORECASE), r'\1=[REDACTED]'),
]


class RedactingFormatter(logging.Formatter):
    """Custom logging formatter that strips sensitive secrets prior to emission."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        redacted = original
        for pattern, replacement in SENSITIVE_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configures root and application loggers with redacting formatters."""
    logger = logging.getLogger("authguard")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplication
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    formatter = RedactingFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(module)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger


logger = setup_logging()
