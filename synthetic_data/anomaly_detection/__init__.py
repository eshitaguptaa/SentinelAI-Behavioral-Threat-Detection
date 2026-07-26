"""Anomaly detection contracts for SentinelAI.

The live detector is the Behavioural Transformer
(``synthetic_data.behavioural_transformer``). This package exposes the shared
``AnomalyPrediction`` schema that risk / explainability / API layers consume.
"""

from synthetic_data.anomaly_detection.scoring import (
    ANOMALY_LABEL,
    NORMAL_LABEL,
    SKLEARN_ANOMALY,
    SKLEARN_NORMAL,
    AnomalyPrediction,
)

__all__ = [
    "ANOMALY_LABEL",
    "NORMAL_LABEL",
    "SKLEARN_ANOMALY",
    "SKLEARN_NORMAL",
    "AnomalyPrediction",
]
