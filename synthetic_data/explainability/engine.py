"""Explainability Engine: RiskAssessment + FeatureVector → RiskExplanation.

Generates deterministic, SOC-friendly narratives. Does not perform machine
learning and does not modify risk scores. Contributing factors and
recommendations are reused from ``RiskAssessment``; observations are derived
solely from ``FeatureVector.ml_features()``.
"""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.explainability.explanations import (
    build_observations,
    summary_for_risk_level,
)
from synthetic_data.explainability.schema import RiskExplanation
from synthetic_data.explainability.validation import (
    FeatureVectorLike,
    RiskAssessmentLike,
    validate_batch_lengths,
    validate_feature_vector,
    validate_pair_alignment,
    validate_risk_assessment,
    validate_risk_explanation,
)


class ExplainabilityEngine:
    """Produce human-readable explanations for enterprise risk assessments."""

    def explain(
        self,
        assessment: RiskAssessmentLike,
        feature_vector: FeatureVectorLike,
    ) -> RiskExplanation:
        """Explain why an employee-day received its calculated risk.

        Args:
            assessment: Phase 10 ``RiskAssessment`` (scores/factors unchanged).
            feature_vector: Matching Phase 8 ``FeatureVector``.

        Returns:
            Validated ``RiskExplanation``.
        """
        validate_risk_assessment(assessment)
        validate_feature_vector(feature_vector)
        validate_pair_alignment(assessment, feature_vector)

        behavioural = feature_vector.ml_features()
        observations = build_observations(behavioural)

        # Reuse assessment factors/recommendation exactly (shallow copy of list).
        explanation = RiskExplanation(
            employee_id=assessment.employee_id,
            simulation_day=assessment.simulation_day,
            risk_score=float(assessment.risk_score),
            risk_level=assessment.risk_level,
            summary=summary_for_risk_level(assessment.risk_level),
            contributing_factors=list(assessment.contributing_factors),
            observations=observations,
            recommendation=assessment.recommendation,
        )
        validate_risk_explanation(explanation)
        return explanation

    def explain_batch(
        self,
        assessments: Sequence[RiskAssessmentLike],
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> list[RiskExplanation]:
        """Explain a batch of aligned assessment / feature-vector pairs."""
        validate_batch_lengths(assessments, feature_vectors)
        results: list[RiskExplanation] = []
        for assessment, vector in zip(assessments, feature_vectors, strict=True):
            results.append(self.explain(assessment, vector))
        return results


_default_engine = ExplainabilityEngine()


def explain(
    assessment: RiskAssessmentLike,
    feature_vector: FeatureVectorLike,
) -> RiskExplanation:
    """Explain one employee-day using the default ``ExplainabilityEngine``."""
    return _default_engine.explain(assessment, feature_vector)


def explain_batch(
    assessments: Sequence[RiskAssessmentLike],
    feature_vectors: Sequence[FeatureVectorLike],
) -> list[RiskExplanation]:
    """Batch-explain using the default ``ExplainabilityEngine``."""
    return _default_engine.explain_batch(assessments, feature_vectors)
