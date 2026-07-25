"""Attack Classification Engine — rule-based labels after the Risk Engine.

Uses ``FeatureVector.ml_features()`` only. Does not call Isolation Forest or
the Risk Engine and never reads simulator attack ground truth.
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

    def classify(self, feature_vector: FeatureVectorLike) -> AttackClassification:
        """Classify one employee-day feature vector."""
        features = feature_vector.ml_features()
        match = evaluate_rules(features)
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
    ) -> list[AttackClassification]:
        """Classify many feature vectors in input order."""
        return [self.classify(vector) for vector in feature_vectors]


_default_engine = AttackClassificationEngine()


def classify_attack(feature_vector: FeatureVectorLike) -> AttackClassification:
    """Classify one vector using the default engine."""
    return _default_engine.classify(feature_vector)


def classify_attacks(
    feature_vectors: Sequence[FeatureVectorLike],
) -> list[AttackClassification]:
    """Batch-classify using the default engine."""
    return _default_engine.classify_batch(feature_vectors)
