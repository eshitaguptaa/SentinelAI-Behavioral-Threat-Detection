"""Explainability Engine: RiskAssessment + FeatureVector → RiskExplanation.

Generates evidence-based SOC narratives that separate Transformer findings
from rule findings. Does not perform machine learning and does not modify
risk scores.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from synthetic_data.explainability.explanations import (
    build_decision_summary,
    build_rule_findings,
    build_transformer_findings,
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
        status: str | None = None,
        confidence: float | None = None,
        behaviour_insight: Mapping[str, Any] | None = None,
    ) -> RiskExplanation:
        """Explain why an employee-day received its calculated risk."""
        validate_risk_assessment(assessment)
        validate_feature_vector(feature_vector)
        validate_pair_alignment(assessment, feature_vector)

        behavioural = feature_vector.ml_features()
        resolved_attack = (attack_type or "None").strip()
        signals = list(matched_signals or [])
        conf = 0.5 if confidence is None else float(confidence)

        transformer_findings = build_transformer_findings(
            anomaly_score=float(assessment.anomaly_score),
            behaviour_insight=behaviour_insight,
        )
        rule_findings = build_rule_findings(
            behavioural,
            attack_type=resolved_attack,
            matched_signals=signals,
        )

        resolved_status = status or "Normal"
        summary = build_decision_summary(
            status=resolved_status,
            risk_score=float(assessment.risk_score),
            attack_type=resolved_attack,
            confidence=conf,
            transformer_findings=transformer_findings,
            rule_findings=rule_findings,
        )

        recommendation = recommendation_for_attack(
            resolved_attack,
            risk_level=assessment.risk_level,
        )

        explanation = RiskExplanation(
            employee_id=assessment.employee_id,
            simulation_day=assessment.simulation_day,
            risk_score=float(assessment.risk_score),
            risk_level=assessment.risk_level,
            summary=summary,
            # API contract: contributing_factors = Transformer findings
            contributing_factors=transformer_findings,
            # API contract: observations = Rule findings
            observations=rule_findings,
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
        statuses: Sequence[str] | None = None,
        confidences: Sequence[float] | None = None,
    ) -> list[RiskExplanation]:
        """Explain a batch of aligned assessment / feature-vector pairs."""
        validate_batch_lengths(assessments, feature_vectors)
        results: list[RiskExplanation] = []
        for index, (assessment, vector) in enumerate(
            zip(assessments, feature_vectors, strict=True)
        ):
            attack = None
            signals: Sequence[str] | None = None
            status = None
            confidence = None
            if attack_types is not None:
                attack = attack_types[index]
            if matched_signals_batch is not None:
                signals = matched_signals_batch[index]
            if statuses is not None:
                status = statuses[index]
            if confidences is not None:
                confidence = confidences[index]
            results.append(
                self.explain(
                    assessment,
                    vector,
                    attack_type=attack,
                    matched_signals=signals,
                    status=status,
                    confidence=confidence,
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
    status: str | None = None,
    confidence: float | None = None,
    behaviour_insight: Mapping[str, Any] | None = None,
) -> RiskExplanation:
    """Explain one employee-day using the default ``ExplainabilityEngine``."""
    return _default_engine.explain(
        assessment,
        feature_vector,
        attack_type=attack_type,
        matched_signals=matched_signals,
        status=status,
        confidence=confidence,
        behaviour_insight=behaviour_insight,
    )


def explain_batch(
    assessments: Sequence[RiskAssessmentLike],
    feature_vectors: Sequence[FeatureVectorLike],
    *,
    attack_types: Sequence[str] | None = None,
    matched_signals_batch: Sequence[Sequence[str]] | None = None,
    statuses: Sequence[str] | None = None,
    confidences: Sequence[float] | None = None,
) -> list[RiskExplanation]:
    """Batch-explain using the default ``ExplainabilityEngine``."""
    return _default_engine.explain_batch(
        assessments,
        feature_vectors,
        attack_types=attack_types,
        matched_signals_batch=matched_signals_batch,
        statuses=statuses,
        confidences=confidences,
    )
