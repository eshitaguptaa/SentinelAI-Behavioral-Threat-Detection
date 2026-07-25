"""Risk Engine: AnomalyPrediction + FeatureVector → RiskAssessment.

Deterministic, explainable, and strictly free of attack ground truth.
Uses ``FeatureVector.ml_features()`` and ``AnomalyPrediction.normalized_score``
only — no machine learning, no randomness, no sklearn/pandas.
"""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.risk_engine.rules import (
    apply_behavioural_rules,
    collect_anomaly_factors,
)
from synthetic_data.risk_engine.schema import RiskAssessment
from synthetic_data.risk_engine.scoring import (
    clamp_score,
    map_risk_level,
    recommendation_for_level,
    risk_level_value,
)
from synthetic_data.risk_engine.validation import (
    AnomalyPredictionLike,
    FeatureVectorLike,
    assert_rules_avoid_forbidden_fields,
    validate_anomaly_prediction,
    validate_batch_lengths,
    validate_feature_vector,
    validate_pair_alignment,
    validate_risk_assessment,
)

# Run once at import: fail fast if rule allow-list is misconfigured.
assert_rules_avoid_forbidden_fields()


class RiskEngine:
    """Enterprise risk scoring engine for SentinelAI employee-day assessments.

    Starting point is ``AnomalyPrediction.normalized_score``. Behavioural
    rules from ``rules.py`` apply bounded uplifts using only
    ``FeatureVector.ml_features()``. Final scores are clamped to ``[0, 100]``.
    """

    def assess_risk(
        self,
        prediction: AnomalyPredictionLike,
        feature_vector: FeatureVectorLike,
    ) -> RiskAssessment:
        """Assess risk for one employee-day.

        Args:
            prediction: Phase 9 anomaly prediction.
            feature_vector: Matching Phase 8 feature vector.

        Returns:
            Validated ``RiskAssessment``.

        Raises:
            RiskEngineError: On invalid inputs or identity mismatch.
        """
        validate_anomaly_prediction(prediction)
        validate_feature_vector(feature_vector)
        validate_pair_alignment(prediction, feature_vector)

        anomaly_score = clamp_score(float(prediction.normalized_score))
        behavioural = feature_vector.ml_features()

        adjustment, rule_factors = apply_behavioural_rules(behavioural)
        # Bound rule uplift so mild Transformer scores are not pushed straight
        # into CRITICAL by stacked heuristics alone.
        adjustment = min(float(adjustment), 20.0)
        risk_score = clamp_score(anomaly_score + adjustment)
        level = map_risk_level(risk_score)

        factors = collect_anomaly_factors(anomaly_score) + rule_factors
        # Deterministic de-duplication preserving order.
        seen: set[str] = set()
        unique_factors: list[str] = []
        for factor in factors:
            if factor not in seen:
                unique_factors.append(factor)
                seen.add(factor)

        assessment = RiskAssessment(
            employee_id=prediction.employee_id,
            simulation_day=prediction.simulation_day,
            anomaly_score=anomaly_score,
            risk_score=risk_score,
            risk_level=risk_level_value(level),
            contributing_factors=unique_factors,
            recommendation=recommendation_for_level(level),
        )
        validate_risk_assessment(assessment)
        return assessment

    def assess_risks(
        self,
        predictions: Sequence[AnomalyPredictionLike],
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> list[RiskAssessment]:
        """Batch-assess risks for aligned prediction / feature-vector pairs.

        Args:
            predictions: Phase 9 predictions in employee-day order.
            feature_vectors: Matching Phase 8 vectors (same order / identities).

        Returns:
            List of ``RiskAssessment`` aligned to the input order.
        """
        validate_batch_lengths(predictions, feature_vectors)
        results: list[RiskAssessment] = []
        for prediction, vector in zip(predictions, feature_vectors, strict=True):
            results.append(self.assess_risk(prediction, vector))
        return results


# Module-level default engine for the functional public API.
_default_engine = RiskEngine()


def assess_risk(
    prediction: AnomalyPredictionLike,
    feature_vector: FeatureVectorLike,
) -> RiskAssessment:
    """Assess risk for one employee-day using the default ``RiskEngine``."""
    return _default_engine.assess_risk(prediction, feature_vector)


def assess_risks(
    predictions: Sequence[AnomalyPredictionLike],
    feature_vectors: Sequence[FeatureVectorLike],
) -> list[RiskAssessment]:
    """Batch-assess risks using the default ``RiskEngine``."""
    return _default_engine.assess_risks(predictions, feature_vectors)
