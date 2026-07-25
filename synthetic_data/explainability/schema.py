"""Explainability schema for SentinelAI Phase 11.

``RiskExplanation`` is a SOC-facing narrative companion to ``RiskAssessment``.
It never changes risk scores and never consumes attack ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

VALID_RISK_LEVELS: Final[frozenset[str]] = frozenset(
    {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
)

# Attack / evaluation-only fields — never used for observations.
FORBIDDEN_EXPLANATION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "label",
        "has_attack",
        "attack_event_count",
        "attack_event_ratio",
        "unique_attack_type_count",
        "impossible_travel_count",
        "credential_theft_count",
        "privilege_escalation_count",
        "data_exfiltration_count",
        "after_hours_attack_count",
        "lateral_movement_count",
        "brute_force_count",
        "max_attack_confidence",
    }
)


@dataclass(slots=True)
class RiskExplanation:
    """Human-readable security explanation for one employee-day.

    Attributes:
        employee_id: Employee identifier (copied from the risk assessment).
        simulation_day: ISO simulation day string.
        risk_score: Final enterprise risk score in ``[0, 100]`` (unchanged).
        risk_level: ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``.
        summary: Deterministic narrative summary for the risk level.
        contributing_factors: Copied from ``RiskAssessment`` (not regenerated).
        observations: Behavioural observations derived from ``ml_features()``.
        recommendation: Copied from ``RiskAssessment`` (not regenerated).
    """

    employee_id: str
    simulation_day: str
    risk_score: float
    risk_level: str
    summary: str
    contributing_factors: list[str]
    observations: list[str]
    recommendation: str
