"""Concept-drift tracking via per-entity EWMA of anomaly scores.

Legitimate behaviour evolves (new devices, shifted hours). A sudden spike is
more suspicious than a gradual climb. We keep an exponential moving average
per entity and dampen scores when the deviation looks like slow drift rather
than an abrupt intrusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Final, Protocol

DEFAULT_ALPHA: Final[float] = 0.20


class AnomalyPredictionLike(Protocol):
    """Minimal prediction shape used by drift adjustment."""

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool
# Absolute gap vs EWMA that counts as abrupt (intrusion-like).
SPIKE_DELTA: Final[float] = 25.0
# Gradual climb band — dampen toward the rolling baseline.
DRIFT_DELTA_MIN: Final[float] = 8.0
DRIFT_DAMPEN: Final[float] = 0.55


@dataclass(slots=True)
class DriftAssessment:
    """Concept-drift diagnosis for one employee-day."""

    entity_id: str
    ewma: float
    delta: float
    is_gradual_drift: bool
    is_abrupt_shift: bool
    reason: str
    adjusted_normalized_score: float


@dataclass
class ConceptDriftTracker:
    """Thread-safe EWMA store for entity anomaly baselines."""

    alpha: float = DEFAULT_ALPHA
    spike_delta: float = SPIKE_DELTA
    drift_delta_min: float = DRIFT_DELTA_MIN
    drift_dampen: float = DRIFT_DAMPEN
    _ewma: dict[str, float] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def assess(
        self,
        entity_id: str,
        normalized_score: float,
    ) -> DriftAssessment:
        """Update EWMA and classify the current observation."""
        score = max(0.0, min(100.0, float(normalized_score)))
        with self._lock:
            previous = self._ewma.get(entity_id)
            if previous is None:
                self._ewma[entity_id] = score
                return DriftAssessment(
                    entity_id=entity_id,
                    ewma=score,
                    delta=0.0,
                    is_gradual_drift=False,
                    is_abrupt_shift=False,
                    reason="First observation for entity — baseline initialised.",
                    adjusted_normalized_score=score,
                )

            delta = score - previous
            abs_delta = abs(delta)
            # Update EWMA with the observed score.
            updated = self.alpha * score + (1.0 - self.alpha) * previous
            self._ewma[entity_id] = updated

        if abs_delta >= self.spike_delta:
            return DriftAssessment(
                entity_id=entity_id,
                ewma=updated,
                delta=delta,
                is_gradual_drift=False,
                is_abrupt_shift=True,
                reason=(
                    f"Abrupt shift vs rolling baseline "
                    f"(Δ={delta:+.1f}, EWMA={previous:.1f})."
                ),
                adjusted_normalized_score=score,
            )

        if abs_delta >= self.drift_delta_min and delta > 0:
            # Gradual upward drift — dampen toward previous baseline.
            adjusted = (
                self.drift_dampen * score + (1.0 - self.drift_dampen) * previous
            )
            adjusted = max(0.0, min(100.0, adjusted))
            return DriftAssessment(
                entity_id=entity_id,
                ewma=updated,
                delta=delta,
                is_gradual_drift=True,
                is_abrupt_shift=False,
                reason=(
                    f"Gradual concept drift vs rolling baseline "
                    f"(Δ={delta:+.1f}); score dampened toward EWMA."
                ),
                adjusted_normalized_score=adjusted,
            )

        return DriftAssessment(
            entity_id=entity_id,
            ewma=updated,
            delta=delta,
            is_gradual_drift=False,
            is_abrupt_shift=False,
            reason="Score consistent with rolling behavioural baseline.",
            adjusted_normalized_score=score,
        )

    def apply(
        self,
        prediction: AnomalyPredictionLike,
        assessment: DriftAssessment,
    ) -> AnomalyPredictionLike:
        """Return prediction with drift-adjusted normalized score when needed."""
        if (
            not assessment.is_gradual_drift
            or assessment.adjusted_normalized_score
            == prediction.normalized_score
        ):
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

    def snapshot(self) -> dict[str, float]:
        """Copy of current EWMA values (for diagnostics / tests)."""
        with self._lock:
            return dict(self._ewma)


_GLOBAL_TRACKER = ConceptDriftTracker()


def get_drift_tracker() -> ConceptDriftTracker:
    """Process-wide drift tracker (API can replace via app.state)."""
    return _GLOBAL_TRACKER


def set_drift_tracker(tracker: ConceptDriftTracker) -> None:
    """Replace the process-wide tracker (used by tests / API lifespan)."""
    global _GLOBAL_TRACKER
    _GLOBAL_TRACKER = tracker


def drift_dict(assessment: DriftAssessment) -> dict[str, Any]:
    """JSON-serializable concept-drift payload for API responses."""
    return {
        "entity_id": assessment.entity_id,
        "ewma": round(assessment.ewma, 4),
        "delta": round(assessment.delta, 4),
        "is_gradual_drift": assessment.is_gradual_drift,
        "is_abrupt_shift": assessment.is_abrupt_shift,
        "reason": assessment.reason,
        "adjusted_normalized_score": round(
            assessment.adjusted_normalized_score, 4
        ),
    }
