"""SentinelAI Risk Engine (Phase 10).

Converts Phase 9 ``AnomalyPrediction`` objects and matching Phase 8
``FeatureVector`` rows into deterministic, explainable ``RiskAssessment``
results for dashboards, APIs, and reports.

Strictly rule-based — no machine learning, no attack ground truth.

Public API::

    from synthetic_data.risk_engine import (
        RiskAssessment,
        RiskEngine,
        assess_risk,
        assess_risks,
    )

    assessment = assess_risk(prediction, feature_vector)
    assessments = assess_risks(predictions, feature_vectors)
"""

from synthetic_data.risk_engine.engine import RiskEngine, assess_risk, assess_risks
from synthetic_data.risk_engine.schema import (
    FORBIDDEN_RISK_FIELDS,
    RiskAssessment,
    RiskLevel,
)
from synthetic_data.risk_engine.scoring import (
    clamp_score,
    map_risk_level,
    recommendation_for_level,
)
from synthetic_data.risk_engine.validation import RiskEngineError

__all__ = [
    "FORBIDDEN_RISK_FIELDS",
    "RiskAssessment",
    "RiskEngine",
    "RiskEngineError",
    "RiskLevel",
    "assess_risk",
    "assess_risks",
    "clamp_score",
    "map_risk_level",
    "recommendation_for_level",
]
