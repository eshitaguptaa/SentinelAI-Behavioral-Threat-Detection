"""Score clamping, risk-level mapping, and recommendation helpers.

Pure functions with no FeatureVector / AnomalyPrediction dependencies.
Business rules for behavioural adjustments live in ``rules.py``.
"""

from __future__ import annotations

from synthetic_data.risk_engine.schema import (
    RISK_LEVEL_BOUNDS,
    RiskLevel,
)

SCORE_MIN: float = 0.0
SCORE_MAX: float = 100.0

_RECOMMENDATIONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "Continue monitoring.",
    RiskLevel.MEDIUM: "Review recent authentication and user activity.",
    RiskLevel.HIGH: "SOC investigation recommended.",
    RiskLevel.CRITICAL: "Immediate incident response required.",
}


def clamp_score(score: float, *, low: float = SCORE_MIN, high: float = SCORE_MAX) -> float:
    """Clamp ``score`` into ``[low, high]``."""
    if score < low:
        return low
    if score > high:
        return high
    return float(score)


def map_risk_level(risk_score: float) -> RiskLevel:
    """Map a clamped risk score onto a ``RiskLevel`` band.

    Bands (inclusive)::

        0–24   LOW
        25–49  MEDIUM
        50–74  HIGH
        75–100 CRITICAL
    """
    score = clamp_score(risk_score)
    if score <= RISK_LEVEL_BOUNDS[RiskLevel.LOW][1]:
        return RiskLevel.LOW
    if score <= RISK_LEVEL_BOUNDS[RiskLevel.MEDIUM][1]:
        return RiskLevel.MEDIUM
    if score <= RISK_LEVEL_BOUNDS[RiskLevel.HIGH][1]:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def recommendation_for_level(level: RiskLevel | str) -> str:
    """Return a level-based recommendation (prefer attack-aware helpers in API)."""
    from synthetic_data.risk_engine.recommendations import recommendation_for_attack

    if isinstance(level, str):
        level_key = level
    else:
        level_key = level.value
    return recommendation_for_attack("Normal Activity", risk_level=level_key)


def risk_level_value(level: RiskLevel) -> str:
    """Return the string form of a ``RiskLevel`` (for ``RiskAssessment``)."""
    return level.value
