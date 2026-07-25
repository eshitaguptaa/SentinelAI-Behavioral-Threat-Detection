"""Enums and dataclasses for the Attack Injection Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class AttackType(str, Enum):
    """Supported insider / identity attack techniques."""

    IMPOSSIBLE_TRAVEL = "IMPOSSIBLE_TRAVEL"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    AFTER_HOURS_ACCESS = "AFTER_HOURS_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    BRUTE_FORCE_LOGIN = "BRUTE_FORCE_LOGIN"


class Severity(str, Enum):
    """Relative severity of an injected attack scenario."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class AttackRecord:
    """Metadata describing one planned or injected attack instance.

    Attributes:
        attack_id: Stable unique identifier for the attack instance.
        employee_id: Primary employee targeted by the attack.
        attack_type: Technique used for the attack.
        severity: Severity classification.
        day: Simulation calendar day associated with the attack.
        description: Human-readable summary of the scenario.
        injected_event_ids: Timeline event IDs created or altered by injection.
        campaign_id: Optional campaign identifier when techniques are chained.
    """

    attack_id: str
    employee_id: str
    attack_type: AttackType
    severity: Severity
    day: date
    description: str
    injected_event_ids: list[str] = field(default_factory=list)
    campaign_id: str | None = None


@dataclass(slots=True)
class AttackTarget:
    """A selected employee/day assignment awaiting technique injection."""

    employee_id: str
    day: date
    attack_type: AttackType
    severity: Severity
    campaign_id: str | None = None


@dataclass(slots=True)
class AttackInjectionSummary:
    """Aggregate counters produced by an injection run."""

    total_input_events: int
    total_output_events: int
    eligible_employees: int
    selected_targets: int
    attacks_planned: int
    attacks_injected: int
    attacks_skipped: int
    by_attack_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AttackInjectionResult:
    """Return payload from the Attack Injection Engine orchestrator."""

    modified_events: list
    attack_records: list[AttackRecord]
    summary: AttackInjectionSummary
