"""Attack Classification Engine — rule-based labels after anomaly detection.

Uses ``FeatureVector.ml_features()`` plus the detector anomaly score when no
signature rule matches. Does not call Transformer training
and never reads simulator attack ground truth.
"""

from __future__ import annotations

from collections.abc import Sequence

from synthetic_data.attack_classification.rules import evaluate_rules
from synthetic_data.attack_classification.schema import AttackClassification
from synthetic_data.attack_classification.validation import (
    FeatureVectorLike,
    validate_classification,
)


class AttackClassificationEngine:
    """Classify likely attack / activity type from behavioural features."""

    def classify(
        self,
        feature_vector: FeatureVectorLike,
        *,
        anomaly_score: float | None = None,
    ) -> AttackClassification:
        """Classify one employee-day feature vector.

        Args:
            feature_vector: Phase 8 features for rule matching.
            anomaly_score: Optional normalised anomaly score ``[0, 100]``.
                Used only when no signature rule matches to choose among
                ``None`` / ``Unknown Behaviour`` / ``Behavioural Anomaly``.
        """
        features = feature_vector.ml_features()
        match = evaluate_rules(features, anomaly_score=anomaly_score)
        result = AttackClassification(
            employee_id=feature_vector.employee_id,
            simulation_day=feature_vector.simulation_day,
            attack_type=match.attack_type.value,
            attack_confidence=float(match.confidence),
            matched_signals=list(match.signals),
        )
        validate_classification(result)
        return result

    def classify_batch(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
        *,
        anomaly_scores: Sequence[float | None] | None = None,
    ) -> list[AttackClassification]:
        """Classify many feature vectors in input order."""
        results: list[AttackClassification] = []
        for index, vector in enumerate(feature_vectors):
            score = None
            if anomaly_scores is not None:
                score = anomaly_scores[index]
            results.append(self.classify(vector, anomaly_score=score))
        return results


_default_engine = AttackClassificationEngine()


def classify_attack(
    feature_vector: FeatureVectorLike,
    *,
    anomaly_score: float | None = None,
) -> AttackClassification:
    """Classify one vector using the default engine."""
    return _default_engine.classify(feature_vector, anomaly_score=anomaly_score)


def classify_attacks(
    feature_vectors: Sequence[FeatureVectorLike],
    *,
    anomaly_scores: Sequence[float | None] | None = None,
) -> list[AttackClassification]:
    """Batch-classify using the default engine."""
    return _default_engine.classify_batch(
        feature_vectors, anomaly_scores=anomaly_scores
    )
