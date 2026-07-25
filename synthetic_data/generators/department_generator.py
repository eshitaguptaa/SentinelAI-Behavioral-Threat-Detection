"""Department structure generator."""

from __future__ import annotations

from synthetic_data.config import DEPARTMENT_DEFINITIONS
from synthetic_data.models import Department


def _department_id(name: str) -> str:
    """Build a stable department identifier from its display name."""
    slug = name.upper().replace(" ", "_")
    return f"DEPT-{slug}"


def generate_departments(
    definitions: list[tuple[str, str]] | None = None,
) -> list[Department]:
    """Create the fixed enterprise department catalog.

    Args:
        definitions: Optional list of ``(name, sensitivity_level)`` pairs.
            Defaults to ``config.DEPARTMENT_DEFINITIONS``.

    Returns:
        Department entities in definition order.
    """
    source = definitions if definitions is not None else list(DEPARTMENT_DEFINITIONS)
    return [
        Department(
            department_id=_department_id(name),
            name=name,
            sensitivity_level=sensitivity,
        )
        for name, sensitivity in source
    ]
