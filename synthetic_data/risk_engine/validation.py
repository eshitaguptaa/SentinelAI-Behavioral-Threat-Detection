"""Validation helpers for the SentinelAI Risk Engine.

Ensures production risk scoring never consumes attack ground truth and that
``RiskAssessment`` objects are structurally sound.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from synthetic_data.risk_engine.rules import ALLOWED_RULE_FEATURES
from synthetic_data.risk_engine.schema import (
    FORBIDDEN_RISK_FIELDS,
    VALID_RISK_LEVELS,
    RiskAssessment,
)
from synthetic_data.risk_engine.scoring import SCORE_MAX, SCORE_MIN


class RiskEngineError(ValueError):
    """Base error for Risk Engine validation / usage failures."""

    def __init__(self, message: str, *, code: str = "risk_error") -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class AnomalyPredictionLike(Protocol):
    """Minimal Phase 9 prediction surface required by the Risk Engine."""

    employee_id: str
    simulation_day: str
    normalized_score: float


@runtime_checkable
class FeatureVectorLike(Protocol):
    """Minimal Phase 8 vector surface required by the Risk Engine."""

    employee_id: str
    simulation_day: str

    def ml_features(self) -> dict[str, float]:
        """Return behavioural features only (no identity / ground truth)."""


def _is_bad_number(value: Any) -> bool:
    """True for None, NaN, or Inf."""
    if value is None:
        return True
    if isinstance(value, float):
        return math.isnan(value) or math.isinf(value)
    return False


def validate_identity_pair(
    *,
    employee_id: str | None,
    simulation_day: str | None,
    context: str,
) -> None:
    """Ensure identity fields are present non-empty strings."""
    if not employee_id or not isinstance(employee_id, str):
        raise RiskEngineError(
            f"{context}: employee_id must be a non-empty string",
            code="invalid_identity",
        )
    if not simulation_day or not isinstance(simulation_day, str):
        raise RiskEngineError(
            f"{context}: simulation_day must be a non-empty string",
            code="invalid_identity",
        )


def validate_anomaly_prediction(prediction: AnomalyPredictionLike) -> None:
    """Validate a Phase 9 anomaly prediction for risk assessment."""
    validate_identity_pair(
        employee_id=getattr(prediction, "employee_id", None),
        simulation_day=getattr(prediction, "simulation_day", None),
        context="AnomalyPrediction",
    )
    score = prediction.normalized_score
    if _is_bad_number(score):
        raise RiskEngineError(
            "anomaly_score (normalized_score) must not be NaN/Inf",
            code="invalid_score",
        )
    score_f = float(score)
    if score_f < SCORE_MIN or score_f > SCORE_MAX:
        raise RiskEngineError(
            f"anomaly_score must be in [{SCORE_MIN}, {SCORE_MAX}], got {score_f}",
            code="invalid_score",
        )


def validate_feature_vector(vector: FeatureVectorLike) -> None:
    """Validate a Phase 8 feature vector identity and behavioural map."""
    validate_identity_pair(
        employee_id=getattr(vector, "employee_id", None),
        simulation_day=getattr(vector, "simulation_day", None),
        context="FeatureVector",
    )
    if not hasattr(vector, "ml_features") or not callable(vector.ml_features):
        raise RiskEngineError(
            "FeatureVector must provide ml_features()",
            code="invalid_features",
        )
    features = vector.ml_features()
    validate_behavioural_features(features)


def validate_behavioural_features(features: Mapping[str, Any]) -> None:
    """Ensure behavioural features contain no forbidden attack keys / bad values."""
    if not isinstance(features, Mapping):
        raise RiskEngineError(
            "ml_features() must return a mapping",
            code="invalid_features",
        )

    leaked = sorted(set(features.keys()) & FORBIDDEN_RISK_FIELDS)
    if leaked:
        raise RiskEngineError(
            "Behavioural features must not include attack ground-truth keys: "
            + ", ".join(leaked),
            code="forbidden_features",
        )

    for name, value in features.items():
        if _is_bad_number(value):
            raise RiskEngineError(
                f"Feature {name!r} is missing/NaN/Inf",
                code="invalid_value",
            )


def validate_pair_alignment(
    prediction: AnomalyPredictionLike,
    vector: FeatureVectorLike,
) -> None:
    """Ensure anomaly prediction and feature vector describe the same employee-day."""
    if prediction.employee_id != vector.employee_id:
        raise RiskEngineError(
            "employee_id mismatch between AnomalyPrediction and FeatureVector: "
            f"{prediction.employee_id!r} vs {vector.employee_id!r}",
            code="identity_mismatch",
        )
    if prediction.simulation_day != vector.simulation_day:
        raise RiskEngineError(
            "simulation_day mismatch between AnomalyPrediction and FeatureVector: "
            f"{prediction.simulation_day!r} vs {vector.simulation_day!r}",
            code="identity_mismatch",
        )


def validate_risk_assessment(assessment: RiskAssessment) -> None:
    """Validate a fully constructed ``RiskAssessment`` instance."""
    validate_identity_pair(
        employee_id=assessment.employee_id,
        simulation_day=assessment.simulation_day,
        context="RiskAssessment",
    )

    for field_name, value in (
        ("anomaly_score", assessment.anomaly_score),
        ("risk_score", assessment.risk_score),
    ):
        if _is_bad_number(value):
            raise RiskEngineError(
                f"{field_name} must not be NaN/Inf",
                code="invalid_score",
            )
        value_f = float(value)
        if value_f < SCORE_MIN or value_f > SCORE_MAX:
            raise RiskEngineError(
                f"{field_name} must be in [{SCORE_MIN}, {SCORE_MAX}], got {value_f}",
                code="invalid_score",
            )

    if assessment.risk_level not in VALID_RISK_LEVELS:
        raise RiskEngineError(
            f"Invalid risk_level: {assessment.risk_level!r}",
            code="invalid_risk_level",
        )

    if not isinstance(assessment.contributing_factors, list):
        raise RiskEngineError(
            "contributing_factors must be a list",
            code="invalid_factors",
        )
    for index, factor in enumerate(assessment.contributing_factors):
        if not isinstance(factor, str) or not factor.strip():
            raise RiskEngineError(
                f"contributing_factors[{index}] must be a non-empty string",
                code="invalid_factors",
            )

    if not isinstance(assessment.recommendation, str) or not assessment.recommendation.strip():
        raise RiskEngineError(
            "recommendation must be a non-empty string",
            code="invalid_recommendation",
        )


def assert_rules_avoid_forbidden_fields() -> None:
    """Static safeguard: rule allow-list must not intersect forbidden fields."""
    overlap = ALLOWED_RULE_FEATURES & FORBIDDEN_RISK_FIELDS
    if overlap:
        raise RiskEngineError(
            "Rule allow-list incorrectly includes forbidden fields: "
            + ", ".join(sorted(overlap)),
            code="forbidden_features",
        )


def validate_batch_lengths(
    predictions: Sequence[Any],
    vectors: Sequence[Any],
) -> None:
    """Ensure paired batch inputs have equal length."""
    if len(predictions) != len(vectors):
        raise RiskEngineError(
            f"Batch length mismatch: {len(predictions)} predictions vs "
            f"{len(vectors)} feature vectors",
            code="batch_mismatch",
        )
