"""Session domain model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class Session:
    """Authenticated access window tying an employee, device, and location.

    Attributes:
        session_id: Stable unique identifier for the session.
        employee_id: Identifier of the authenticated employee.
        device_id: Identifier of the device used for the session.
        location_id: Identifier of the observed or claimed location.
        login_time: Session start timestamp (timezone-aware preferred).
        logout_time: Session end timestamp, if the session has ended.
        ip_address: Client IP address observed at login.
    """

    session_id: str
    employee_id: str
    device_id: str
    location_id: str
    login_time: datetime
    logout_time: datetime | None = None
    ip_address: str | None = None
