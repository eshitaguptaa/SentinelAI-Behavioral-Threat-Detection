"""Shared anomaly prediction schema for SentinelAI detectors.

``AnomalyPrediction`` is the contract consumed by the Risk Engine,
explainability layer, and API — independent of the underlying detector.
"""

from __future__ import annotations

from dataclasses import dataclass

# Binary labels used on ``AnomalyPrediction.prediction`` (legacy-compatible).
ANOMALY_LABEL: int = -1
NORMAL_LABEL: int = 1

# Back-compat aliases (older call sites / docs).
SKLEARN_ANOMALY: int = ANOMALY_LABEL
SKLEARN_NORMAL: int = NORMAL_LABEL


@dataclass(slots=True)
class AnomalyPrediction:
    """Anomaly detection result for one employee-day.

    This object is the interface consumed by the Risk Engine, explainability
    layer, and dashboard. It does **not** include attack labels or risk levels.

    Attributes:
        employee_id: Employee identifier (metadata only; not a model feature).
        simulation_day: ISO simulation day (metadata only).
        raw_score: Detector-native score (Transformer: negative reconstruction error).
        normalized_score: Anomalousness in ``[0, 100]`` (higher → more anomalous).
        prediction: ``-1`` anomaly, ``1`` normal.
        is_anomaly: ``True`` when ``prediction == -1``.
    """

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool
