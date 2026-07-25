"""Scoring helpers: raw Isolation Forest outputs → AnomalyPrediction objects.

Normalization maps sklearn decision scores onto a 0–100 anomalousness scale
where 0 is completely normal and 100 is extremely anomalous.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from synthetic_data.anomaly_detection.validation import (
    AnomalyDetectionError,
    validate_score_arrays,
)

# sklearn IsolationForest predict labels.
SKLEARN_ANOMALY: int = -1
SKLEARN_NORMAL: int = 1


@dataclass(slots=True)
class AnomalyPrediction:
    """Anomaly detection result for one employee-day.

    This object is the interface consumed by the Risk Engine, explainability
    layer, and dashboard. It does **not** include attack labels or risk levels.

    Attributes:
        employee_id: Employee identifier (metadata only; not a model feature).
        simulation_day: ISO simulation day (metadata only).
        raw_score: sklearn ``decision_function`` value (higher → more normal).
        normalized_score: Anomalousness in ``[0, 100]`` (higher → more anomalous).
        prediction: sklearn label: ``-1`` anomaly, ``1`` normal.
        is_anomaly: ``True`` when ``prediction == -1``.
    """

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool


@dataclass(slots=True)
class ScoreNormalizer:
    """Maps inverted decision scores onto ``[0, 100]`` using fit-time range.

    During ``fit``, Isolation Forest ``decision_function`` values are inverted
    (``-score``) so larger values mean more anomalous. Min/max of the training
    inverted scores define the scale. Prediction-time values are clipped.
    """

    score_min: float
    score_max: float

    @classmethod
    def from_decision_scores(cls, decision_scores: np.ndarray) -> ScoreNormalizer:
        """Fit normalizer from training ``decision_function`` outputs."""
        if decision_scores.size == 0:
            raise AnomalyDetectionError(
                "Cannot fit score normalizer on empty scores",
                code="empty_dataset",
            )
        inverted = -np.asarray(decision_scores, dtype=np.float64)
        score_min = float(np.min(inverted))
        score_max = float(np.max(inverted))
        # Degenerate range (all identical scores): keep a unit span around value.
        if math_isclose(score_min, score_max):
            score_min -= 0.5
            score_max += 0.5
        return cls(score_min=score_min, score_max=score_max)

    def normalize(self, decision_scores: np.ndarray) -> np.ndarray:
        """Convert decision scores to anomalousness in ``[0, 100]``."""
        inverted = -np.asarray(decision_scores, dtype=np.float64)
        span = self.score_max - self.score_min
        scaled = (inverted - self.score_min) / span * 100.0
        return np.clip(scaled, 0.0, 100.0)


def math_isclose(a: float, b: float, *, rel_tol: float = 1e-9) -> bool:
    """Local isclose helper (avoids importing math solely for one call site)."""
    return abs(a - b) <= rel_tol * max(abs(a), abs(b), 1.0)


def prediction_to_is_anomaly(prediction: int) -> bool:
    """Map sklearn prediction label to a boolean anomaly flag."""
    return int(prediction) == SKLEARN_ANOMALY


def build_anomaly_predictions(
    *,
    identities: Sequence[tuple[str, str]],
    raw_scores: np.ndarray,
    predictions: np.ndarray,
    normalizer: ScoreNormalizer,
) -> list[AnomalyPrediction]:
    """Assemble ``AnomalyPrediction`` objects for a batch.

    Args:
        identities: ``(employee_id, simulation_day)`` aligned to rows.
        raw_scores: ``decision_function`` outputs (higher = more normal).
        predictions: sklearn ``predict`` labels (``-1`` / ``1``).
        normalizer: Fit-time score normalizer.
    """
    n = len(identities)
    validate_score_arrays(
        raw_scores=raw_scores,
        predictions=predictions,
        n_samples=n,
    )
    normalized = normalizer.normalize(raw_scores)

    results: list[AnomalyPrediction] = []
    for index in range(n):
        pred = int(predictions[index])
        results.append(
            AnomalyPrediction(
                employee_id=identities[index][0],
                simulation_day=identities[index][1],
                raw_score=float(raw_scores[index]),
                normalized_score=float(normalized[index]),
                prediction=pred,
                is_anomaly=prediction_to_is_anomaly(pred),
            )
        )
    return results
