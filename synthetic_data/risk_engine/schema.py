"""Risk assessment schema and risk-level taxonomy for SentinelAI Phase 10.

``RiskAssessment`` is the enterprise interface consumed by explainability,
dashboard, FastAPI, and reporting layers. It contains no ML outputs beyond the
already-computed anomaly score and never embeds attack ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class RiskLevel(str, Enum):
    """Ordered enterprise risk severity bands."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Inclusive score bounds for each band: [low, high].
RISK_LEVEL_BOUNDS: Final[dict[RiskLevel, tuple[float, float]]] = {
    RiskLevel.LOW: (0.0, 24.0),
    RiskLevel.MEDIUM: (25.0, 49.0),
    RiskLevel.HIGH: (50.0, 74.0),
    RiskLevel.CRITICAL: (75.0, 100.0),
}

VALID_RISK_LEVELS: Final[frozenset[str]] = frozenset(level.value for level in RiskLevel)

# Attack / evaluation-only fields that must NEVER influence production risk.
FORBIDDEN_RISK_FIELDS: Final[frozenset[str]] = frozenset(
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
        "device_spoofing_count",
        "low_and_slow_count",
        "insider_drift_count",
        "max_attack_confidence",
    }
)


@dataclass(slots=True)
class RiskAssessment:
    """Enterprise cybersecurity risk assessment for one employee-day.

    Attributes:
        employee_id: Employee identifier.
        simulation_day: ISO simulation day string.
        anomaly_score: Phase 9 normalized anomaly score in ``[0, 100]``.
        risk_score: Final enterprise risk score in ``[0, 100]``.
        risk_level: One of ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``.
        contributing_factors: Deterministic human-readable explanations.
        recommendation: Deterministic SOC-facing guidance for ``risk_level``.
    """

    employee_id: str
    simulation_day: str
    anomaly_score: float
    risk_score: float
    risk_level: str
    contributing_factors: list[str]
    recommendation: str
