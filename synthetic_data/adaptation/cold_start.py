"""Cold-start handling for entities with insufficient behavioural history.

When an employee-day has too few events (or looks like a brand-new identity),
raw reconstruction scores are unreliable. We shrink the anomaly score toward
a neutral prior and surface an explicit cold-start flag for analysts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Protocol

from synthetic_data.feature_engineering.feature_schema import FeatureVector


class AnomalyPredictionLike(Protocol):
    """Minimal prediction shape used by cold-start adjustment."""

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool

# Below this event count, treat the observation as cold-start.
MIN_EVENTS_FOR_FULL_TRUST: Final[int] = 25
# Extremely thin history — stronger shrink.
MIN_EVENTS_HARD_COLD: Final[int] = 8
# Neutral prior used when shrinking (middle of LOW band).
NEUTRAL_ANOMALY_PRIOR: Final[float] = 18.0


@dataclass(slots=True)
class ColdStartAssessment:
    """Cold-start diagnosis for one employee-day."""

    is_cold_start: bool
    event_count: int
    trust: float
    """Blend weight on the raw model score in ``[0, 1]`` (1 = full trust)."""
    reason: str
    adjusted_normalized_score: float


def _event_count(vector: FeatureVector) -> int:
    try:
        return int(getattr(vector, "total_events", 0) or 0)
    except (TypeError, ValueError):
        return 0


def assess_cold_start(
    vector: FeatureVector,
    prediction: AnomalyPredictionLike,
    *,
    min_events: int = MIN_EVENTS_FOR_FULL_TRUST,
    hard_min: int = MIN_EVENTS_HARD_COLD,
    prior: float = NEUTRAL_ANOMALY_PRIOR,
) -> ColdStartAssessment:
    """Return cold-start status and a shrunk anomaly score when needed.

    Shrink formula (Bayesian-style toward org prior)::

        trust = clamp(event_count / min_events, 0, 1)
        adjusted = trust * raw + (1 - trust) * prior
    """
    count = _event_count(vector)
    raw = float(prediction.normalized_score)

    if count >= min_events:
        return ColdStartAssessment(
            is_cold_start=False,
            event_count=count,
            trust=1.0,
            reason="Sufficient event history for full detector trust.",
            adjusted_normalized_score=raw,
        )

    trust = max(0.0, min(1.0, count / float(min_events)))
    if count < hard_min:
        trust = min(trust, 0.25)
        reason = (
            f"Hard cold-start: only {count} events "
            f"(<{hard_min}); score shrunk toward org prior {prior:.0f}."
        )
    else:
        reason = (
            f"Cold-start: {count} events below full-trust threshold "
            f"({min_events}); score partially shrunk toward prior {prior:.0f}."
        )

    adjusted = trust * raw + (1.0 - trust) * prior
    adjusted = max(0.0, min(100.0, adjusted))
    return ColdStartAssessment(
        is_cold_start=True,
        event_count=count,
        trust=trust,
        reason=reason,
        adjusted_normalized_score=adjusted,
    )


def apply_cold_start(
    prediction: AnomalyPredictionLike,
    assessment: ColdStartAssessment,
) -> AnomalyPredictionLike:
    """Return a copy of ``prediction`` with cold-start-adjusted scores."""
    if not assessment.is_cold_start:
        return prediction

    from synthetic_data.anomaly_detection.scoring import AnomalyPrediction

    adjusted = float(assessment.adjusted_normalized_score)
    is_anomaly = adjusted >= 50.0
    return AnomalyPrediction(
        employee_id=prediction.employee_id,
        simulation_day=prediction.simulation_day,
        raw_score=prediction.raw_score,
        normalized_score=adjusted,
        prediction=-1 if is_anomaly else 1,
        is_anomaly=is_anomaly,
    )


def cold_start_dict(assessment: ColdStartAssessment) -> dict[str, Any]:
    """JSON-serializable cold-start payload for API responses."""
    return {
        "is_cold_start": assessment.is_cold_start,
        "event_count": assessment.event_count,
        "trust": round(assessment.trust, 4),
        "reason": assessment.reason,
        "adjusted_normalized_score": round(assessment.adjusted_normalized_score, 4),
    }
