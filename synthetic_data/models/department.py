"""Department domain model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Department:
    """Organizational unit used to scope access and risk context.

    Attributes:
        department_id: Stable unique identifier for the department.
        name: Human-readable department name.
        sensitivity_level: Relative sensitivity of the department's data
            and operations (for example: low, medium, high, critical).
    """

    department_id: str
    name: str
    sensitivity_level: str = "medium"
