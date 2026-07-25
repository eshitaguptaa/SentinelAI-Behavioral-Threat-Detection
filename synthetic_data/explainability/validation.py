"""Validation helpers for the SentinelAI Explainability Engine."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from synthetic_data.explainability.schema import (
    FORBIDDEN_EXPLANATION_FIELDS,
    VALID_RISK_LEVELS,
    RiskExplanation,
)

SCORE_MIN: float = 0.0
SCORE_MAX: float = 100.0


class ExplainabilityError(ValueError):
    """Base error for explainability validation / usage failures."""

    def __init__(self, message: str, *, code: str = "explainability_error") -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class RiskAssessmentLike(Protocol):
    """Minimal Phase 10 risk assessment surface."""

    employee_id: str
    simulation_day: str
    risk_score: float
    risk_level: str
    contributing_factors: list[str]
    recommendation: str


@runtime_checkable
class FeatureVectorLike(Protocol):
    """Minimal Phase 8 feature vector surface."""

    employee_id: str
    simulation_day: str

    def ml_features(self) -> dict[str, float]:
        """Return behavioural features only."""


def _is_bad_number(value: Any) -> bool:
    """True for None, NaN, or Inf."""
    if value is None:
        return True
    if isinstance(value, float):
        return math.isnan(value) or math.isinf(value)
    return False


def validate_identity(
    *,
    employee_id: str | None,
    simulation_day: str | None,
    context: str,
) -> None:
    """Ensure identity fields are present non-empty strings."""
    if not employee_id or not isinstance(employee_id, str):
        raise ExplainabilityError(
            f"{context}: employee_id must be a non-empty string",
            code="invalid_identity",
        )
    if not simulation_day or not isinstance(simulation_day, str):
        raise ExplainabilityError(
            f"{context}: simulation_day must be a non-empty string",
            code="invalid_identity",
        )


def validate_risk_assessment(assessment: RiskAssessmentLike) -> None:
    """Validate a Phase 10 risk assessment used as explainability input."""
    validate_identity(
        employee_id=getattr(assessment, "employee_id", None),
        simulation_day=getattr(assessment, "simulation_day", None),
        context="RiskAssessment",
    )
    score = assessment.risk_score
    if _is_bad_number(score):
        raise ExplainabilityError(
            "risk_score must not be NaN/Inf",
            code="invalid_score",
        )
    score_f = float(score)
    if score_f < SCORE_MIN or score_f > SCORE_MAX:
        raise ExplainabilityError(
            f"risk_score must be in [{SCORE_MIN}, {SCORE_MAX}], got {score_f}",
            code="invalid_score",
        )
    if assessment.risk_level not in VALID_RISK_LEVELS:
        raise ExplainabilityError(
            f"Invalid risk_level: {assessment.risk_level!r}",
            code="invalid_risk_level",
        )
    if not isinstance(assessment.contributing_factors, list):
        raise ExplainabilityError(
            "contributing_factors must be a list",
            code="invalid_factors",
        )
    for index, factor in enumerate(assessment.contributing_factors):
        if not isinstance(factor, str):
            raise ExplainabilityError(
                f"contributing_factors[{index}] must be a string",
                code="invalid_factors",
            )
    if not isinstance(assessment.recommendation, str) or not assessment.recommendation.strip():
        raise ExplainabilityError(
            "recommendation must be a non-empty string",
            code="invalid_recommendation",
        )


def validate_feature_vector(vector: FeatureVectorLike) -> None:
    """Validate a Phase 8 feature vector for observation generation."""
    validate_identity(
        employee_id=getattr(vector, "employee_id", None),
        simulation_day=getattr(vector, "simulation_day", None),
        context="FeatureVector",
    )
    if not hasattr(vector, "ml_features") or not callable(vector.ml_features):
        raise ExplainabilityError(
            "FeatureVector must provide ml_features()",
            code="invalid_features",
        )
    features = vector.ml_features()
    validate_behavioural_features(features)


def validate_behavioural_features(features: Mapping[str, Any]) -> None:
    """Ensure behavioural features contain no forbidden attack keys / bad values."""
    if not isinstance(features, Mapping):
        raise ExplainabilityError(
            "ml_features() must return a mapping",
            code="invalid_features",
        )
    leaked = sorted(set(features.keys()) & FORBIDDEN_EXPLANATION_FIELDS)
    if leaked:
        raise ExplainabilityError(
            "Behavioural features must not include attack ground-truth keys: "
            + ", ".join(leaked),
            code="forbidden_features",
        )
    for name, value in features.items():
        if _is_bad_number(value):
            raise ExplainabilityError(
                f"Feature {name!r} is missing/NaN/Inf",
                code="invalid_value",
            )


def validate_pair_alignment(
    assessment: RiskAssessmentLike,
    vector: FeatureVectorLike,
) -> None:
    """Ensure assessment and feature vector describe the same employee-day."""
    if assessment.employee_id != vector.employee_id:
        raise ExplainabilityError(
            "employee_id mismatch between RiskAssessment and FeatureVector: "
            f"{assessment.employee_id!r} vs {vector.employee_id!r}",
            code="identity_mismatch",
        )
    if assessment.simulation_day != vector.simulation_day:
        raise ExplainabilityError(
            "simulation_day mismatch between RiskAssessment and FeatureVector: "
            f"{assessment.simulation_day!r} vs {vector.simulation_day!r}",
            code="identity_mismatch",
        )


def validate_risk_explanation(explanation: RiskExplanation) -> None:
    """Validate a fully constructed ``RiskExplanation``."""
    validate_identity(
        employee_id=explanation.employee_id,
        simulation_day=explanation.simulation_day,
        context="RiskExplanation",
    )
    if _is_bad_number(explanation.risk_score):
        raise ExplainabilityError(
            "risk_score must not be NaN/Inf",
            code="invalid_score",
        )
    score_f = float(explanation.risk_score)
    if score_f < SCORE_MIN or score_f > SCORE_MAX:
        raise ExplainabilityError(
            f"risk_score must be in [{SCORE_MIN}, {SCORE_MAX}], got {score_f}",
            code="invalid_score",
        )
    if explanation.risk_level not in VALID_RISK_LEVELS:
        raise ExplainabilityError(
            f"Invalid risk_level: {explanation.risk_level!r}",
            code="invalid_risk_level",
        )
    if not isinstance(explanation.summary, str) or not explanation.summary.strip():
        raise ExplainabilityError(
            "summary must be a non-empty string",
            code="invalid_summary",
        )
    if not isinstance(explanation.recommendation, str) or not explanation.recommendation.strip():
        raise ExplainabilityError(
            "recommendation must be a non-empty string",
            code="invalid_recommendation",
        )
    if not isinstance(explanation.contributing_factors, list):
        raise ExplainabilityError(
            "contributing_factors must be a list",
            code="invalid_factors",
        )
    for index, factor in enumerate(explanation.contributing_factors):
        if not isinstance(factor, str):
            raise ExplainabilityError(
                f"contributing_factors[{index}] must be a string",
                code="invalid_factors",
            )
    if not isinstance(explanation.observations, list):
        raise ExplainabilityError(
            "observations must be a list",
            code="invalid_observations",
        )
    for index, observation in enumerate(explanation.observations):
        if not isinstance(observation, str):
            raise ExplainabilityError(
                f"observations[{index}] must be a string",
                code="invalid_observations",
            )


def validate_batch_lengths(
    assessments: Sequence[Any],
    vectors: Sequence[Any],
) -> None:
    """Ensure paired batch inputs have equal length."""
    if len(assessments) != len(vectors):
        raise ExplainabilityError(
            f"Batch length mismatch: {len(assessments)} assessments vs "
            f"{len(vectors)} feature vectors",
            code="batch_mismatch",
        )
