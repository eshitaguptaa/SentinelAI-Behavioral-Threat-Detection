"""Deterministic Attack Classification Engine (rule-based, no ML).

Runs after the Risk Engine and labels employee-day behaviour using only
``FeatureVector.ml_features()``.

Public API::

    from synthetic_data.attack_classification import (
        AttackClassification,
        AttackClassificationEngine,
        AttackType,
        classify_attack,
        classify_attacks,
    )
"""

from synthetic_data.attack_classification.engine import (
    AttackClassificationEngine,
    classify_attack,
    classify_attacks,
)
from synthetic_data.attack_classification.schema import AttackClassification, AttackType
from synthetic_data.attack_classification.validation import AttackClassificationError

__all__ = [
    "AttackClassification",
    "AttackClassificationEngine",
    "AttackClassificationError",
    "AttackType",
    "classify_attack",
    "classify_attacks",
]
