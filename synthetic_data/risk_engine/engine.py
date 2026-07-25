"""Risk Engine: AnomalyPrediction + FeatureVector → RiskAssessment.

Deterministic, explainable, and strictly free of attack ground truth.

Final risk is a **weighted fusion** (see ``config.RiskEngineConfig``)::

    risk = 0.55 * anomaly + 0.20 * behaviour + 0.15 * rule + 0.10 * confidence

not a raw copy of the anomaly score.
"""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG, RiskEngineConfig
from synthetic_data.risk_engine.fusion import (
    compute_behaviour_score,
    compute_rule_score,
    confidence_from_anomaly_score,
    fuse_risk_score,
)
from synthetic_data.risk_engine.rules import collect_anomaly_factors
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

    Combines Transformer/IF anomaly scores with behavioural suspicion, attack
    rule severity, and model confidence via ``RiskEngineConfig`` weights.
    """

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        self.config = config or DEFAULT_RISK_CONFIG
        self.config.validate()

    def assess_risk(
        self,
        prediction: AnomalyPredictionLike,
        feature_vector: FeatureVectorLike,
        *,
        attack_confidence: float = 0.0,
        model_confidence: float | None = None,
    ) -> RiskAssessment:
        """Assess risk for one employee-day.

        Args:
            prediction: Phase 9 anomaly prediction.
            feature_vector: Matching Phase 8 feature vector.
            attack_confidence: Rule-engine confidence (0–1 or 0–100).
            model_confidence: Optional Transformer certainty (0–1 or 0–100).
                When omitted, derived from the anomaly score band.

        Returns:
            Validated ``RiskAssessment``.
        """
        validate_anomaly_prediction(prediction)
        validate_feature_vector(feature_vector)
        validate_pair_alignment(prediction, feature_vector)

        anomaly_score = clamp_score(float(prediction.normalized_score))
        behavioural = feature_vector.ml_features()

        behaviour_score, rule_factors = compute_behaviour_score(
            behavioural, config=self.config
        )
        rule_score = compute_rule_score(attack_confidence)

        if model_confidence is None:
            confidence = confidence_from_anomaly_score(
                anomaly_score, config=self.config
            )
        else:
            conf = float(model_confidence)
            confidence = conf * 100.0 if conf <= 1.0 else conf
            confidence = clamp_score(confidence)

        risk_score = fuse_risk_score(
            anomaly_score=anomaly_score,
            behaviour_score=behaviour_score,
            rule_score=rule_score,
            confidence=confidence,
            config=self.config,
        )
        level = map_risk_level(risk_score)

        factors = collect_anomaly_factors(anomaly_score) + rule_factors
        seen: set[str] = set()
        unique_factors: list[str] = []
        for factor in factors:
            if factor and factor not in seen:
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
        *,
        attack_confidences: Sequence[float] | None = None,
        model_confidences: Sequence[float | None] | None = None,
    ) -> list[RiskAssessment]:
        """Batch-assess risks for aligned prediction / feature-vector pairs."""
        validate_batch_lengths(predictions, feature_vectors)
        results: list[RiskAssessment] = []
        for index, (prediction, vector) in enumerate(
            zip(predictions, feature_vectors, strict=True)
        ):
            attack_conf = 0.0
            model_conf: float | None = None
            if attack_confidences is not None:
                attack_conf = float(attack_confidences[index])
            if model_confidences is not None:
                model_conf = model_confidences[index]
            results.append(
                self.assess_risk(
                    prediction,
                    vector,
                    attack_confidence=attack_conf,
                    model_confidence=model_conf,
                )
            )
        return results


# Module-level default engine for the functional public API.
_default_engine = RiskEngine()


def assess_risk(
    prediction: AnomalyPredictionLike,
    feature_vector: FeatureVectorLike,
    *,
    attack_confidence: float = 0.0,
    model_confidence: float | None = None,
) -> RiskAssessment:
    """Assess risk for one employee-day using the default ``RiskEngine``."""
    return _default_engine.assess_risk(
        prediction,
        feature_vector,
        attack_confidence=attack_confidence,
        model_confidence=model_confidence,
    )


def assess_risks(
    predictions: Sequence[AnomalyPredictionLike],
    feature_vectors: Sequence[FeatureVectorLike],
    *,
    attack_confidences: Sequence[float] | None = None,
    model_confidences: Sequence[float | None] | None = None,
) -> list[RiskAssessment]:
    """Batch-assess risks using the default ``RiskEngine``."""
    return _default_engine.assess_risks(
        predictions,
        feature_vectors,
        attack_confidences=attack_confidences,
        model_confidences=model_confidences,
    )
