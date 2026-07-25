"""Enterprise aggregate domain model."""

from __future__ import annotations

from dataclasses import dataclass, field

from .department import Department
from .device import Device
from .employee import Employee
from .location import Location
from .resource import Resource


@dataclass(slots=True)
class Enterprise:
    """Complete enterprise structure snapshot (no behavioral events).

    Attributes:
        departments: Organizational units in the company.
        locations: Office locations available to employees.
        employees: Workforce identities, including hierarchy via manager_id.
        devices: Trusted endpoints assigned to employees.
        resources: Corporate systems and data assets.
    """

    departments: list[Department] = field(default_factory=list)
    locations: list[Location] = field(default_factory=list)
    employees: list[Employee] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
