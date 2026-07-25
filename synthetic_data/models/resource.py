"""Resource domain model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Resource:
    """Protected system, application, or data asset.

    Attributes:
        resource_id: Stable unique identifier for the resource.
        resource_name: Human-readable resource name.
        category: Resource category (for example: app, database, file_share).
        sensitivity: Sensitivity classification of the resource.
        allowed_departments: Department identifiers permitted to access
            the resource under normal policy.
    """

    resource_id: str
    resource_name: str
    category: str = "application"
    sensitivity: str = "medium"
    allowed_departments: list[str] = field(default_factory=list)
