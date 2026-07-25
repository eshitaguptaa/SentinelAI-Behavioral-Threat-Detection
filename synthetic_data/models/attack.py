"""Attack domain model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Attack:
    """Labeled attack scenario used for evaluation and simulation contexts.

    Attributes:
        attack_id: Stable unique identifier for the attack scenario.
        attack_type: Attack category (for example: credential_stuffing,
            insider_exfiltration, privilege_escalation).
        severity: Relative severity of the attack.
        description: Short human-readable summary of the attack.
        affected_employee_ids: Employee identifiers involved in the scenario.
        injected_event_ids: Event identifiers that belong to the attack trail.
    """

    attack_id: str
    attack_type: str
    severity: str = "medium"
    description: str = ""
    affected_employee_ids: list[str] = field(default_factory=list)
    injected_event_ids: list[str] = field(default_factory=list)
