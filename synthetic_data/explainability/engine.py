"""Explainability Engine: RiskAssessment + FeatureVector → RiskExplanation.

Generates evidence-based SOC narratives. Does not perform machine learning
and does not modify risk scores.
"""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.explainability.explanations import (
    build_observations,
    summary_for_detection,
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
from synthetic_data.risk_engine.recommendations import recommendation_for_attack


class ExplainabilityEngine:
    """Produce human-readable explanations for enterprise risk assessments."""

    def explain(
        self,
        assessment: RiskAssessmentLike,
        feature_vector: FeatureVectorLike,
        *,
        attack_type: str | None = None,
        matched_signals: Sequence[str] | None = None,
    ) -> RiskExplanation:
        """Explain why an employee-day received its calculated risk."""
        validate_risk_assessment(assessment)
        validate_feature_vector(feature_vector)
        validate_pair_alignment(assessment, feature_vector)

        behavioural = feature_vector.ml_features()
        observations = build_observations(behavioural)
        resolved_attack = (attack_type or "Normal Activity").strip()
        signals = list(matched_signals or [])

        recommendation = recommendation_for_attack(
            resolved_attack,
            risk_level=assessment.risk_level,
        )

        explanation = RiskExplanation(
            employee_id=assessment.employee_id,
            simulation_day=assessment.simulation_day,
            risk_score=float(assessment.risk_score),
            risk_level=assessment.risk_level,
            summary=summary_for_detection(
                risk_level=assessment.risk_level,
                attack_type=resolved_attack,
                matched_signals=signals,
            ),
            contributing_factors=list(assessment.contributing_factors),
            observations=observations,
            recommendation=recommendation,
        )
        validate_risk_explanation(explanation)
        return explanation

    def explain_batch(
        self,
        assessments: Sequence[RiskAssessmentLike],
        feature_vectors: Sequence[FeatureVectorLike],
        *,
        attack_types: Sequence[str] | None = None,
        matched_signals_batch: Sequence[Sequence[str]] | None = None,
    ) -> list[RiskExplanation]:
        """Explain a batch of aligned assessment / feature-vector pairs."""
        validate_batch_lengths(assessments, feature_vectors)
        results: list[RiskExplanation] = []
        for index, (assessment, vector) in enumerate(
            zip(assessments, feature_vectors, strict=True)
        ):
            attack = None
            signals: Sequence[str] | None = None
            if attack_types is not None:
                attack = attack_types[index]
            if matched_signals_batch is not None:
                signals = matched_signals_batch[index]
            results.append(
                self.explain(
                    assessment,
                    vector,
                    attack_type=attack,
                    matched_signals=signals,
                )
            )
        return results


_default_engine = ExplainabilityEngine()


def explain(
    assessment: RiskAssessmentLike,
    feature_vector: FeatureVectorLike,
    *,
    attack_type: str | None = None,
    matched_signals: Sequence[str] | None = None,
) -> RiskExplanation:
    """Explain one employee-day using the default ``ExplainabilityEngine``."""
    return _default_engine.explain(
        assessment,
        feature_vector,
        attack_type=attack_type,
        matched_signals=matched_signals,
    )


def explain_batch(
    assessments: Sequence[RiskAssessmentLike],
    feature_vectors: Sequence[FeatureVectorLike],
    *,
    attack_types: Sequence[str] | None = None,
    matched_signals_batch: Sequence[Sequence[str]] | None = None,
) -> list[RiskExplanation]:
    """Batch-explain using the default ``ExplainabilityEngine``."""
    return _default_engine.explain_batch(
        assessments,
        feature_vectors,
        attack_types=attack_types,
        matched_signals_batch=matched_signals_batch,
    )
