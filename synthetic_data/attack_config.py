"""Configuration for the SentinelAI Attack Injection Engine.

All knobs live here so attack volume, severity mix, and enabled techniques
can be tuned without changing injector code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from synthetic_data.attack_types import AttackType, Severity


@dataclass(slots=True)
class AttackConfig:
    """Runtime configuration for attack-target selection and injection.

    Attributes:
        attack_ratio: Fraction of eligible employees selected as attack
            targets (0.0–1.0). Example: ``0.05`` ≈ 5% of the workforce.
        random_seed: Seed for reproducible target selection / injection.
        severity_distribution: Relative weights per severity level. Weights
            are normalized at use time and need not sum to 1.0.
        enabled_attack_types: Attack techniques permitted for this run.
        campaign_probability: Chance that a selected target participates in
            a multi-technique campaign rather than a single attack.
        allow_multiple_attacks_per_employee: When True, an employee may be
            assigned more than one attack (or campaign techniques).
        max_attacks_per_employee: Cap applied when multiple attacks are
            allowed for a single employee.
        min_events_for_eligibility: Employees with fewer timeline events
            than this threshold are skipped as targets.
    """

    attack_ratio: float = 0.05
    random_seed: int | None = 42
    severity_distribution: dict[Severity, float] = field(
        default_factory=lambda: {
            Severity.LOW: 0.15,
            Severity.MEDIUM: 0.40,
            Severity.HIGH: 0.30,
            Severity.CRITICAL: 0.15,
        }
    )
    enabled_attack_types: tuple[AttackType, ...] = field(
        default_factory=lambda: tuple(AttackType)
    )
    campaign_probability: float = 0.20
    allow_multiple_attacks_per_employee: bool = False
    max_attacks_per_employee: int = 2
    min_events_for_eligibility: int = 20

    def normalized_severity_weights(self) -> dict[Severity, float]:
        """Return severity weights normalized to sum to 1.0."""
        raw = {
            severity: max(0.0, float(weight))
            for severity, weight in self.severity_distribution.items()
        }
        total = sum(raw.values())
        if total <= 0:
            equal = 1.0 / len(Severity)
            return {severity: equal for severity in Severity}
        return {severity: weight / total for severity, weight in raw.items()}

    def resolve_enabled_types(
        self,
        override: Sequence[AttackType] | None = None,
    ) -> tuple[AttackType, ...]:
        """Return the effective enabled attack-type set."""
        if override is not None:
            return tuple(override)
        if not self.enabled_attack_types:
            return tuple(AttackType)
        return tuple(self.enabled_attack_types)


# Module-level defaults for convenient imports / quick experiments.
DEFAULT_ATTACK_CONFIG = AttackConfig()

ATTACK_RATIO = DEFAULT_ATTACK_CONFIG.attack_ratio
RANDOM_SEED = DEFAULT_ATTACK_CONFIG.random_seed
SEVERITY_DISTRIBUTION = DEFAULT_ATTACK_CONFIG.severity_distribution
ENABLED_ATTACK_TYPES = DEFAULT_ATTACK_CONFIG.enabled_attack_types
CAMPAIGN_PROBABILITY = DEFAULT_ATTACK_CONFIG.campaign_probability
ALLOW_MULTIPLE_ATTACKS_PER_EMPLOYEE = (
    DEFAULT_ATTACK_CONFIG.allow_multiple_attacks_per_employee
)
