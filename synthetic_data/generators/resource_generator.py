"""Enterprise resource catalog generator."""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.models import Department, Resource

# Catalog entries: name, category, sensitivity, allowed department names.
# Department names are resolved to IDs at generation time.
_RESOURCE_CATALOG: list[tuple[str, str, str, list[str]]] = [
    ("GitHub", "development", "High", ["Engineering", "IT"]),
    ("GitLab", "development", "High", ["Engineering", "IT"]),
    ("Source Code Repository", "development", "Critical", ["Engineering", "IT"]),
    ("Jira", "collaboration", "Medium", ["Engineering", "IT", "Operations"]),
    ("Confluence", "collaboration", "Medium", ["Engineering", "IT", "Operations", "Marketing", "Sales"]),
    ("Knowledge Base", "collaboration", "Low", [
        "Engineering",
        "IT",
        "Finance",
        "Human Resources",
        "Sales",
        "Marketing",
        "Legal",
        "Operations",
    ]),
    ("Slack", "communication", "Medium", [
        "Engineering",
        "IT",
        "Finance",
        "Human Resources",
        "Sales",
        "Marketing",
        "Legal",
        "Operations",
    ]),
    ("Microsoft Teams", "communication", "Medium", [
        "Engineering",
        "IT",
        "Finance",
        "Human Resources",
        "Sales",
        "Marketing",
        "Legal",
        "Operations",
    ]),
    ("Email", "communication", "Medium", [
        "Engineering",
        "IT",
        "Finance",
        "Human Resources",
        "Sales",
        "Marketing",
        "Legal",
        "Operations",
    ]),
    ("VPN", "infrastructure", "High", [
        "Engineering",
        "IT",
        "Finance",
        "Human Resources",
        "Sales",
        "Marketing",
        "Legal",
        "Operations",
    ]),
    ("AWS Console", "cloud", "Critical", ["Engineering", "IT", "Operations"]),
    ("Azure Portal", "cloud", "Critical", ["Engineering", "IT", "Operations"]),
    ("HR Portal", "hr", "High", ["Human Resources", "Operations"]),
    ("Payroll", "hr", "Critical", ["Human Resources", "Finance"]),
    ("Finance Database", "finance", "Critical", ["Finance", "Legal"]),
    ("CRM", "sales", "High", ["Sales", "Marketing", "Finance"]),
]


def _resource_id(name: str) -> str:
    """Build a stable resource identifier from its display name."""
    slug = name.upper().replace(" ", "_")
    return f"RES-{slug}"


def generate_resources(departments: Sequence[Department]) -> list[Resource]:
    """Create the enterprise resource catalog.

    Args:
        departments: Department entities used to resolve allowed-department IDs.

    Returns:
        Resource entities with category, sensitivity, and allowed departments.
    """
    departments_by_name = {department.name: department for department in departments}

    resources: list[Resource] = []
    for name, category, sensitivity, allowed_names in _RESOURCE_CATALOG:
        allowed_ids = [
            departments_by_name[dept_name].department_id
            for dept_name in allowed_names
            if dept_name in departments_by_name
        ]
        # If a catalog entry listed unknown departments only, fall back to all.
        if not allowed_ids:
            allowed_ids = [department.department_id for department in departments]

        resources.append(
            Resource(
                resource_id=_resource_id(name),
                resource_name=name,
                category=category,
                sensitivity=sensitivity,
                allowed_departments=allowed_ids,
            )
        )

    return resources
