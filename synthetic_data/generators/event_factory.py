"""Timeline event types and factory helpers for normal workday simulation.

Event-type constants are defined in ``event_catalog`` and re-exported here so
existing imports (``from ...event_factory import LOGIN``) keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from synthetic_data.generators.event_catalog import (
    ADMIN_LOGIN,
    ALL_EVENT_TYPES,
    ANALYTICS_ACCESS,
    API_REQUEST,
    APPLICATION_ACCESS,
    AUTH_EVENT_TYPES,
    AWS_CONSOLE,
    AZURE_PORTAL,
    BREAK_END,
    BREAK_START,
    CANVA_ACCESS,
    CRM_ACCESS,
    DATABASE_ACCESS,
    DEVICE_CONNECT,
    DEVICE_DISCONNECT,
    DOCKER_ACCESS,
    DOCUMENT_ACCESS,
    EMAIL_ACCESS,
    EXCEL_ACCESS,
    FAILED_LOGIN,
    FILE_ACCESS,
    FILE_DELETE,
    FILE_DOWNLOAD,
    FILE_READ,
    FILE_UPLOAD,
    FILE_WRITE,
    GITHUB_ACCESS,
    GIT_PULL,
    GIT_PUSH,
    HR_RECORDS_ACCESS,
    JIRA_ACCESS,
    LOGIN,
    LOGOUT,
    MEETING_JOIN,
    MFA_FAILURE,
    MFA_SUCCESS,
    PASSWORD_CHANGE,
    PAYROLL_ACCESS,
    POLICY_CHANGE,
    PRIVILEGE_ESCALATION,
    REMOTE_DESKTOP,
    RESOURCE_ACCESS,
    RESOURCE_TOUCH_TYPES,
    SLACK_ACCESS,
    SSH_LOGIN,
    TEAMS_ACCESS,
    USB_INSERT,
    USB_REMOVE,
    VPN_CONNECT,
    VPN_DISCONNECT,
)

# Backward-compatible alias used throughout the codebase.
EVENT_TYPES: tuple[str, ...] = ALL_EVENT_TYPES

__all__ = [
    "ADMIN_LOGIN",
    "ALL_EVENT_TYPES",
    "ANALYTICS_ACCESS",
    "API_REQUEST",
    "APPLICATION_ACCESS",
    "AUTH_EVENT_TYPES",
    "AWS_CONSOLE",
    "AZURE_PORTAL",
    "BREAK_END",
    "BREAK_START",
    "CANVA_ACCESS",
    "CRM_ACCESS",
    "DATABASE_ACCESS",
    "DEVICE_CONNECT",
    "DEVICE_DISCONNECT",
    "DOCKER_ACCESS",
    "DOCUMENT_ACCESS",
    "EMAIL_ACCESS",
    "EVENT_TYPES",
    "EXCEL_ACCESS",
    "EventFactory",
    "FAILED_LOGIN",
    "FILE_ACCESS",
    "FILE_DELETE",
    "FILE_DOWNLOAD",
    "FILE_READ",
    "FILE_UPLOAD",
    "FILE_WRITE",
    "GITHUB_ACCESS",
    "GIT_PULL",
    "GIT_PUSH",
    "HR_RECORDS_ACCESS",
    "JIRA_ACCESS",
    "LOGIN",
    "LOGOUT",
    "MEETING_JOIN",
    "MFA_FAILURE",
    "MFA_SUCCESS",
    "PASSWORD_CHANGE",
    "PAYROLL_ACCESS",
    "POLICY_CHANGE",
    "PRIVILEGE_ESCALATION",
    "REMOTE_DESKTOP",
    "RESOURCE_ACCESS",
    "RESOURCE_TOUCH_TYPES",
    "SLACK_ACCESS",
    "SSH_LOGIN",
    "TEAMS_ACCESS",
    "TimelineEvent",
    "USB_INSERT",
    "USB_REMOVE",
    "VPN_CONNECT",
    "VPN_DISCONNECT",
]


@dataclass(slots=True)
class TimelineEvent:
    """A single chronological activity in an employee's workday timeline.

    Attributes:
        event_id: Stable unique identifier for the event.
        employee_id: Employee who performed the activity.
        timestamp: When the activity occurred.
        event_type: One of the supported timeline event types.
        device_id: Device used for the activity.
        location_id: Observed or claimed location at event time.
        session_id: Session this event belongs to.
        resource_id: Optional target resource identifier.
        browser: Browser used, when applicable.
        operating_system: OS used, when applicable.
        result: Outcome of the activity (normal timelines use success).
        metadata: Optional extensible details.
    """

    event_id: str
    employee_id: str
    timestamp: datetime
    event_type: str
    device_id: str
    location_id: str
    session_id: str
    resource_id: str | None = None
    browser: str | None = None
    operating_system: str | None = None
    result: str = "success"
    metadata: dict[str, Any] = field(default_factory=dict)


class EventFactory:
    """Creates ``TimelineEvent`` instances with monotonic identifiers."""

    def __init__(self, *, start_index: int = 1) -> None:
        self._next_index = start_index

    def create(
        self,
        *,
        employee_id: str,
        timestamp: datetime,
        event_type: str,
        device_id: str,
        location_id: str,
        session_id: str,
        resource_id: str | None = None,
        browser: str | None = None,
        operating_system: str | None = None,
        result: str = "success",
        metadata: dict[str, Any] | None = None,
    ) -> TimelineEvent:
        """Build the next timeline event."""
        event_id = f"EVT-{self._next_index:08d}"
        self._next_index += 1
        return TimelineEvent(
            event_id=event_id,
            employee_id=employee_id,
            timestamp=timestamp,
            event_type=event_type,
            device_id=device_id,
            location_id=location_id,
            session_id=session_id,
            resource_id=resource_id,
            browser=browser,
            operating_system=operating_system,
            result=result,
            metadata=dict(metadata or {}),
        )
