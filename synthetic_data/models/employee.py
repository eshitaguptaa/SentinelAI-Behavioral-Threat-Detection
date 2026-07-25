"""Employee domain model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Employee:
    """Workforce identity used across sessions, devices, and events.

    Relationships are expressed only via identifier fields.

    Attributes:
        employee_id: Stable unique identifier for the employee.
        full_name: Display name of the employee.
        email: Corporate email address.
        department_id: Identifier of the employee's department.
        role: Job role or title used for access context.
        manager_id: Identifier of the reporting manager, if any.
        office_location_id: Identifier of the primary office location.
        timezone: IANA timezone for the employee's typical work context.
        work_start_hour: Typical workday start hour in 24-hour local time.
        work_end_hour: Typical workday end hour in 24-hour local time.
        assigned_device_ids: Identifiers of devices assigned to the employee.
    """

    employee_id: str
    full_name: str
    email: str
    department_id: str
    role: str = "employee"
    manager_id: str | None = None
    office_location_id: str | None = None
    timezone: str = "UTC"
    work_start_hour: int = 9
    work_end_hour: int = 17
    assigned_device_ids: list[str] = field(default_factory=list)
