"""
AuthGuard Test Suite: Security Primitives & RBAC
================================================
"""

import pytest
from app.core.security import (
    constant_time_compare,
    generate_secure_token,
    generate_session_id,
    hash_password,
    verify_password,
)
from app.core.permissions import PermissionEnum, RoleEnum, user_has_permission


def test_password_hashing_and_verification():
    raw_pwd = "SuperSecretPassword123!"
    hashed = hash_password(raw_pwd)

    assert hashed != raw_pwd
    assert hashed.startswith("$2b$")
    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_constant_time_compare():
    tok1 = "token_abc_123"
    tok2 = "token_abc_123"
    tok3 = "token_xyz_999"

    assert constant_time_compare(tok1, tok2) is True
    assert constant_time_compare(tok1, tok3) is False


def test_token_generation_entropy():
    t1 = generate_secure_token(32)
    t2 = generate_secure_token(32)
    s1 = generate_session_id()

    assert len(t1) == 64  # 32 bytes hex
    assert len(t2) == 64
    assert t1 != t2
    assert len(s1) > 20


def test_role_based_permissions():
    # Admin has all permissions
    assert user_has_permission("admin", PermissionEnum.ADMIN_USERS) is True
    assert user_has_permission("admin", PermissionEnum.ASSESSMENT_CREATE) is True

    # Auditor can create assessments but cannot manage admin users
    assert user_has_permission("auditor", PermissionEnum.ASSESSMENT_CREATE) is True
    assert user_has_permission("auditor", PermissionEnum.ADMIN_USERS) is False

    # Viewer has read-only permissions
    assert user_has_permission("viewer", PermissionEnum.ASSESSMENT_READ) is True
    assert user_has_permission("viewer", PermissionEnum.ASSESSMENT_CREATE) is False
