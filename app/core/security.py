"""
AuthGuard Core Security Primitives
==================================
Cryptographic routines: bcrypt password hashing, constant-time verification,
cryptographically strong session identifiers, and CSRF token generation.
"""

import hmac
import os
import secrets
from typing import Optional
import bcrypt


def hash_password(plain_password: str) -> str:
    """Hash password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time verification of password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate cryptographically secure hexadecimal token."""
    return secrets.token_hex(nbytes)


def generate_session_id() -> str:
    """Generate high-entropy session identifier."""
    return secrets.token_urlsafe(32)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Prevent timing side-channel attacks during token comparisons."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))
