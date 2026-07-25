"""Timeline event types and factory helpers for normal workday simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# Supported normal-behavior event types.
DEVICE_CONNECT = "DEVICE_CONNECT"
LOGIN = "LOGIN"
VPN_CONNECT = "VPN_CONNECT"
VPN_DISCONNECT = "VPN_DISCONNECT"
APPLICATION_ACCESS = "APPLICATION_ACCESS"
RESOURCE_ACCESS = "RESOURCE_ACCESS"
EMAIL_ACCESS = "EMAIL_ACCESS"
MEETING_JOIN = "MEETING_JOIN"
FILE_ACCESS = "FILE_ACCESS"
BREAK_START = "BREAK_START"
BREAK_END = "BREAK_END"
LOGOUT = "LOGOUT"

EVENT_TYPES: tuple[str, ...] = (
    DEVICE_CONNECT,
    LOGIN,
    VPN_CONNECT,
    VPN_DISCONNECT,
    APPLICATION_ACCESS,
    RESOURCE_ACCESS,
    EMAIL_ACCESS,
    MEETING_JOIN,
    FILE_ACCESS,
    BREAK_START,
    BREAK_END,
    LOGOUT,
)


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
