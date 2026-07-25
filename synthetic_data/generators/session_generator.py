"""Session helpers for normal workday timeline simulation."""

from __future__ import annotations

from datetime import datetime

from faker import Faker

from synthetic_data.models import Session


class SessionFactory:
    """Creates ``Session`` entities with monotonic identifiers."""

    def __init__(self, *, start_index: int = 1) -> None:
        self._next_index = start_index

    def create(
        self,
        *,
        employee_id: str,
        device_id: str,
        location_id: str,
        login_time: datetime,
        logout_time: datetime | None = None,
        faker: Faker | None = None,
    ) -> Session:
        """Build the next authenticated session."""
        fake = faker or Faker()
        session_id = f"SESS-{self._next_index:08d}"
        self._next_index += 1
        return Session(
            session_id=session_id,
            employee_id=employee_id,
            device_id=device_id,
            location_id=location_id,
            login_time=login_time,
            logout_time=logout_time,
            ip_address=fake.ipv4_private(),
        )
