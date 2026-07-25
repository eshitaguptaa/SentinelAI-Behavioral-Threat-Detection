"""Role- and department-aware activity catalogs for realistic sessions.

Employees from different departments emit different mid-session event mixes
while sharing a common connect → login → … → logout skeleton.
"""

from __future__ import annotations

from typing import Final

from synthetic_data.generators.event_catalog import (
    ANALYTICS_ACCESS,
    API_REQUEST,
    AWS_CONSOLE,
    AZURE_PORTAL,
    CANVA_ACCESS,
    CRM_ACCESS,
    DATABASE_ACCESS,
    DOCUMENT_ACCESS,
    DOCKER_ACCESS,
    EMAIL_ACCESS,
    EXCEL_ACCESS,
    FILE_DOWNLOAD,
    FILE_READ,
    FILE_UPLOAD,
    FILE_WRITE,
    GITHUB_ACCESS,
    GIT_PULL,
    GIT_PUSH,
    HR_RECORDS_ACCESS,
    JIRA_ACCESS,
    MEETING_JOIN,
    MFA_SUCCESS,
    PAYROLL_ACCESS,
    SLACK_ACCESS,
    TEAMS_ACCESS,
)

# Weighted mid-session activities: (event_type, relative_weight)
ActivityWeights = tuple[tuple[str, float], ...]

ENGINEERING_ACTIVITIES: Final[ActivityWeights] = (
    (GITHUB_ACCESS, 4.0),
    (GIT_PULL, 3.0),
    (GIT_PUSH, 2.5),
    (JIRA_ACCESS, 3.5),
    (DOCKER_ACCESS, 2.0),
    (AWS_CONSOLE, 2.5),
    (SLACK_ACCESS, 2.0),
    (EMAIL_ACCESS, 1.5),
    (FILE_READ, 1.5),
    (FILE_WRITE, 1.2),
    (API_REQUEST, 1.5),
    (TEAMS_ACCESS, 1.0),
)

IT_SECURITY_ACTIVITIES: Final[ActivityWeights] = (
    (AWS_CONSOLE, 3.5),
    (AZURE_PORTAL, 3.0),
    (JIRA_ACCESS, 2.5),
    (SLACK_ACCESS, 2.0),
    (EMAIL_ACCESS, 1.5),
    (API_REQUEST, 2.0),
    (FILE_READ, 1.5),
    (DATABASE_ACCESS, 1.5),
    (TEAMS_ACCESS, 1.2),
    (MFA_SUCCESS, 0.8),
)

FINANCE_ACTIVITIES: Final[ActivityWeights] = (
    (DATABASE_ACCESS, 4.0),
    (EXCEL_ACCESS, 3.5),
    (PAYROLL_ACCESS, 3.0),
    (FILE_READ, 2.5),
    (FILE_WRITE, 2.0),
    (EMAIL_ACCESS, 2.5),
    (TEAMS_ACCESS, 1.5),
    (DOCUMENT_ACCESS, 1.5),
    (FILE_DOWNLOAD, 1.0),
)

HR_ACTIVITIES: Final[ActivityWeights] = (
    (EMAIL_ACCESS, 4.0),
    (DOCUMENT_ACCESS, 3.5),
    (HR_RECORDS_ACCESS, 4.0),
    (FILE_READ, 2.5),
    (FILE_WRITE, 1.5),
    (TEAMS_ACCESS, 2.0),
    (SLACK_ACCESS, 1.0),
    (FILE_DOWNLOAD, 1.2),
)

SALES_ACTIVITIES: Final[ActivityWeights] = (
    (CRM_ACCESS, 5.0),
    (EMAIL_ACCESS, 4.0),
    (TEAMS_ACCESS, 3.5),
    (SLACK_ACCESS, 2.0),
    (FILE_READ, 1.5),
    (FILE_UPLOAD, 1.2),
    (DOCUMENT_ACCESS, 1.5),
    (MEETING_JOIN, 2.0),
)

MARKETING_ACTIVITIES: Final[ActivityWeights] = (
    (ANALYTICS_ACCESS, 4.0),
    (CANVA_ACCESS, 3.5),
    (EMAIL_ACCESS, 3.5),
    (SLACK_ACCESS, 2.5),
    (TEAMS_ACCESS, 2.0),
    (FILE_UPLOAD, 1.5),
    (FILE_READ, 1.5),
    (DOCUMENT_ACCESS, 1.5),
)

LEGAL_ACTIVITIES: Final[ActivityWeights] = (
    (DOCUMENT_ACCESS, 4.5),
    (EMAIL_ACCESS, 3.5),
    (FILE_READ, 3.0),
    (FILE_WRITE, 2.0),
    (TEAMS_ACCESS, 2.0),
    (FILE_DOWNLOAD, 1.5),
)

OPERATIONS_ACTIVITIES: Final[ActivityWeights] = (
    (AWS_CONSOLE, 3.0),
    (AZURE_PORTAL, 2.5),
    (JIRA_ACCESS, 3.0),
    (API_REQUEST, 2.5),
    (SLACK_ACCESS, 2.0),
    (EMAIL_ACCESS, 1.5),
    (DATABASE_ACCESS, 1.5),
    (TEAMS_ACCESS, 1.2),
)

DEFAULT_ACTIVITIES: Final[ActivityWeights] = (
    (EMAIL_ACCESS, 3.0),
    (TEAMS_ACCESS, 2.5),
    (SLACK_ACCESS, 2.0),
    (FILE_READ, 2.0),
    (FILE_WRITE, 1.5),
    (DOCUMENT_ACCESS, 1.5),
)

_DEPARTMENT_MAP: Final[dict[str, ActivityWeights]] = {
    "Engineering": ENGINEERING_ACTIVITIES,
    "IT": IT_SECURITY_ACTIVITIES,
    "Finance": FINANCE_ACTIVITIES,
    "Human Resources": HR_ACTIVITIES,
    "Sales": SALES_ACTIVITIES,
    "Marketing": MARKETING_ACTIVITIES,
    "Legal": LEGAL_ACTIVITIES,
    "Operations": OPERATIONS_ACTIVITIES,
}


def activities_for_employee(*, department: str, role: str) -> ActivityWeights:
    """Return weighted mid-session activities for a department/role."""
    catalog = _DEPARTMENT_MAP.get(department, DEFAULT_ACTIVITIES)
    role_key = role.lower()

    # Soft role tweaks within a department.
    if "intern" in role_key:
        # Interns lean toward communication and read-only work.
        return catalog + (
            (EMAIL_ACCESS, 2.0),
            (SLACK_ACCESS, 2.0),
            (FILE_READ, 2.0),
        )
    if role in {"Director", "Manager"}:
        return catalog + (
            (TEAMS_ACCESS, 2.5),
            (EMAIL_ACCESS, 2.5),
            (MEETING_JOIN, 2.0),
        )
    return catalog
