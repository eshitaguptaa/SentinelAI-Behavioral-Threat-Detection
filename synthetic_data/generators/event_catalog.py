"""Enterprise event-type catalog for SentinelAI behavioural simulation.

Expands the original workday event set with authentication, collaboration,
file, developer, cloud, network, device, and security activities used by
role-based session generation and the Transformer sequence pipeline.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

LOGIN: Final[str] = "LOGIN"
LOGOUT: Final[str] = "LOGOUT"
FAILED_LOGIN: Final[str] = "FAILED_LOGIN"
PASSWORD_CHANGE: Final[str] = "PASSWORD_CHANGE"
MFA_SUCCESS: Final[str] = "MFA_SUCCESS"
MFA_FAILURE: Final[str] = "MFA_FAILURE"
ADMIN_LOGIN: Final[str] = "ADMIN_LOGIN"

# ---------------------------------------------------------------------------
# Communication
# ---------------------------------------------------------------------------

EMAIL_ACCESS: Final[str] = "EMAIL_ACCESS"
SLACK_ACCESS: Final[str] = "SLACK_ACCESS"
TEAMS_ACCESS: Final[str] = "TEAMS_ACCESS"
MEETING_JOIN: Final[str] = "MEETING_JOIN"

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

FILE_ACCESS: Final[str] = "FILE_ACCESS"
FILE_READ: Final[str] = "FILE_READ"
FILE_WRITE: Final[str] = "FILE_WRITE"
FILE_DELETE: Final[str] = "FILE_DELETE"
FILE_UPLOAD: Final[str] = "FILE_UPLOAD"
FILE_DOWNLOAD: Final[str] = "FILE_DOWNLOAD"

# ---------------------------------------------------------------------------
# Developer
# ---------------------------------------------------------------------------

GITHUB_ACCESS: Final[str] = "GITHUB_ACCESS"
GIT_PULL: Final[str] = "GIT_PULL"
GIT_PUSH: Final[str] = "GIT_PUSH"
JIRA_ACCESS: Final[str] = "JIRA_ACCESS"
DOCKER_ACCESS: Final[str] = "DOCKER_ACCESS"

# ---------------------------------------------------------------------------
# Cloud / data
# ---------------------------------------------------------------------------

AWS_CONSOLE: Final[str] = "AWS_CONSOLE"
AZURE_PORTAL: Final[str] = "AZURE_PORTAL"
DATABASE_ACCESS: Final[str] = "DATABASE_ACCESS"
APPLICATION_ACCESS: Final[str] = "APPLICATION_ACCESS"
RESOURCE_ACCESS: Final[str] = "RESOURCE_ACCESS"

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

VPN_CONNECT: Final[str] = "VPN_CONNECT"
VPN_DISCONNECT: Final[str] = "VPN_DISCONNECT"
SSH_LOGIN: Final[str] = "SSH_LOGIN"
REMOTE_DESKTOP: Final[str] = "REMOTE_DESKTOP"
API_REQUEST: Final[str] = "API_REQUEST"

# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

DEVICE_CONNECT: Final[str] = "DEVICE_CONNECT"
DEVICE_DISCONNECT: Final[str] = "DEVICE_DISCONNECT"
USB_INSERT: Final[str] = "USB_INSERT"
USB_REMOVE: Final[str] = "USB_REMOVE"

# ---------------------------------------------------------------------------
# Security / policy
# ---------------------------------------------------------------------------

PRIVILEGE_ESCALATION: Final[str] = "PRIVILEGE_ESCALATION"
POLICY_CHANGE: Final[str] = "POLICY_CHANGE"

# ---------------------------------------------------------------------------
# Breaks (legacy workday skeleton)
# ---------------------------------------------------------------------------

BREAK_START: Final[str] = "BREAK_START"
BREAK_END: Final[str] = "BREAK_END"

# Department-specific extras
CRM_ACCESS: Final[str] = "CRM_ACCESS"
ANALYTICS_ACCESS: Final[str] = "ANALYTICS_ACCESS"
CANVA_ACCESS: Final[str] = "CANVA_ACCESS"
PAYROLL_ACCESS: Final[str] = "PAYROLL_ACCESS"
EXCEL_ACCESS: Final[str] = "EXCEL_ACCESS"
HR_RECORDS_ACCESS: Final[str] = "HR_RECORDS_ACCESS"
DOCUMENT_ACCESS: Final[str] = "DOCUMENT_ACCESS"

ALL_EVENT_TYPES: Final[tuple[str, ...]] = (
    LOGIN,
    LOGOUT,
    FAILED_LOGIN,
    PASSWORD_CHANGE,
    MFA_SUCCESS,
    MFA_FAILURE,
    ADMIN_LOGIN,
    EMAIL_ACCESS,
    SLACK_ACCESS,
    TEAMS_ACCESS,
    MEETING_JOIN,
    FILE_ACCESS,
    FILE_READ,
    FILE_WRITE,
    FILE_DELETE,
    FILE_UPLOAD,
    FILE_DOWNLOAD,
    GITHUB_ACCESS,
    GIT_PULL,
    GIT_PUSH,
    JIRA_ACCESS,
    DOCKER_ACCESS,
    AWS_CONSOLE,
    AZURE_PORTAL,
    DATABASE_ACCESS,
    APPLICATION_ACCESS,
    RESOURCE_ACCESS,
    VPN_CONNECT,
    VPN_DISCONNECT,
    SSH_LOGIN,
    REMOTE_DESKTOP,
    API_REQUEST,
    DEVICE_CONNECT,
    DEVICE_DISCONNECT,
    USB_INSERT,
    USB_REMOVE,
    PRIVILEGE_ESCALATION,
    POLICY_CHANGE,
    BREAK_START,
    BREAK_END,
    CRM_ACCESS,
    ANALYTICS_ACCESS,
    CANVA_ACCESS,
    PAYROLL_ACCESS,
    EXCEL_ACCESS,
    HR_RECORDS_ACCESS,
    DOCUMENT_ACCESS,
)

# Events that count as authentication for feature engineering.
AUTH_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        LOGIN,
        LOGOUT,
        FAILED_LOGIN,
        PASSWORD_CHANGE,
        MFA_SUCCESS,
        MFA_FAILURE,
        ADMIN_LOGIN,
        VPN_CONNECT,
        VPN_DISCONNECT,
    }
)

# Events that touch resources / apps / files.
RESOURCE_TOUCH_TYPES: Final[frozenset[str]] = frozenset(
    {
        APPLICATION_ACCESS,
        RESOURCE_ACCESS,
        FILE_ACCESS,
        FILE_READ,
        FILE_WRITE,
        FILE_DELETE,
        FILE_UPLOAD,
        FILE_DOWNLOAD,
        EMAIL_ACCESS,
        SLACK_ACCESS,
        TEAMS_ACCESS,
        MEETING_JOIN,
        GITHUB_ACCESS,
        GIT_PULL,
        GIT_PUSH,
        JIRA_ACCESS,
        DOCKER_ACCESS,
        AWS_CONSOLE,
        AZURE_PORTAL,
        DATABASE_ACCESS,
        SSH_LOGIN,
        REMOTE_DESKTOP,
        API_REQUEST,
        CRM_ACCESS,
        ANALYTICS_ACCESS,
        CANVA_ACCESS,
        PAYROLL_ACCESS,
        EXCEL_ACCESS,
        HR_RECORDS_ACCESS,
        DOCUMENT_ACCESS,
        ADMIN_LOGIN,
        PRIVILEGE_ESCALATION,
        POLICY_CHANGE,
    }
)
