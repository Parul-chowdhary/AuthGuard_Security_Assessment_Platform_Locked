"""
AuthGuard Role-Based Access Control (RBAC)
==========================================
Role and permission declarations and authorization decision logic.
"""

from enum import Enum
from typing import Set


class RoleEnum(str, Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class PermissionEnum(str, Enum):
    # Assessment management
    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_CANCEL = "assessment:cancel"
    ASSESSMENT_DELETE = "assessment:delete"

    # Findings & Evidence
    FINDING_READ = "finding:read"
    FINDING_UPDATE = "finding:update"
    EVIDENCE_READ = "evidence:read"

    # Reporting
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    REPORT_DOWNLOAD = "report:download"

    # Targets & Scope
    TARGET_MANAGE = "target:manage"

    # Administration
    ADMIN_USERS = "admin:users"
    ADMIN_AUDIT = "admin:audit"
    ADMIN_SETTINGS = "admin:settings"


# Role-to-Permissions Mapping Matrix
ROLE_PERMISSIONS: dict[RoleEnum, Set[PermissionEnum]] = {
    RoleEnum.ADMIN: {
        PermissionEnum.ASSESSMENT_READ,
        PermissionEnum.ASSESSMENT_CREATE,
        PermissionEnum.ASSESSMENT_CANCEL,
        PermissionEnum.ASSESSMENT_DELETE,
        PermissionEnum.FINDING_READ,
        PermissionEnum.FINDING_UPDATE,
        PermissionEnum.EVIDENCE_READ,
        PermissionEnum.REPORT_READ,
        PermissionEnum.REPORT_GENERATE,
        PermissionEnum.REPORT_DOWNLOAD,
        PermissionEnum.TARGET_MANAGE,
        PermissionEnum.ADMIN_USERS,
        PermissionEnum.ADMIN_AUDIT,
        PermissionEnum.ADMIN_SETTINGS,
    },
    RoleEnum.AUDITOR: {
        PermissionEnum.ASSESSMENT_READ,
        PermissionEnum.ASSESSMENT_CREATE,
        PermissionEnum.ASSESSMENT_CANCEL,
        PermissionEnum.FINDING_READ,
        PermissionEnum.FINDING_UPDATE,
        PermissionEnum.EVIDENCE_READ,
        PermissionEnum.REPORT_READ,
        PermissionEnum.REPORT_GENERATE,
        PermissionEnum.REPORT_DOWNLOAD,
    },
    RoleEnum.VIEWER: {
        PermissionEnum.ASSESSMENT_READ,
        PermissionEnum.FINDING_READ,
        PermissionEnum.EVIDENCE_READ,
        PermissionEnum.REPORT_READ,
        PermissionEnum.REPORT_DOWNLOAD,
    },
}


def user_has_permission(role: str, permission: PermissionEnum) -> bool:
    """Check if the given user role possesses the requested permission."""
    try:
        role_enum = RoleEnum(role)
        perms = ROLE_PERMISSIONS.get(role_enum, set())
        return permission in perms
    except ValueError:
        return False
