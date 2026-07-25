"""SentinelAI Explainability Engine (Phase 11).

Converts a Phase 10 ``RiskAssessment`` and matching Phase 8 ``FeatureVector``
into a SOC-friendly ``RiskExplanation``. Rule-based and deterministic — no
machine learning, no score mutation, no attack ground truth.

Public API::

    from synthetic_data.explainability import (
        ExplainabilityEngine,
        RiskExplanation,
        explain,
        explain_batch,
    )

    explanation = explain(assessment, feature_vector)
    explanations = explain_batch(assessments, feature_vectors)
"""

from synthetic_data.explainability.engine import (
    ExplainabilityEngine,
    explain,
    explain_batch,
)
from synthetic_data.explainability.schema import RiskExplanation
from synthetic_data.explainability.validation import ExplainabilityError

__all__ = [
    "ExplainabilityEngine",
    "ExplainabilityError",
    "RiskExplanation",
    "explain",
    "explain_batch",
]
