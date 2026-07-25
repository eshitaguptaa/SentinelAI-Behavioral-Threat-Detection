"""Event domain model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    """Atomic activity record observed within a session.

    Attributes:
        event_id: Stable unique identifier for the event.
        timestamp: When the event occurred (timezone-aware preferred).
        employee_id: Identifier of the employee associated with the event.
        session_id: Identifier of the session in which the event occurred.
        resource_id: Identifier of the resource targeted by the event.
        event_type: Event classification (for example: login, read, download).
        result: Outcome of the event (for example: success, failure, denied).
        metadata: Extensible key/value payload for event-specific details.
    """

    event_id: str
    timestamp: datetime
    employee_id: str
    session_id: str
    resource_id: str
    event_type: str
    result: str = "success"
    metadata: dict[str, Any] = field(default_factory=dict)
