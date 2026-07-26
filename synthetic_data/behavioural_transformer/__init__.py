"""Transformer-based behavioural anomaly detection for SentinelAI.

Heavy torch-backed symbols load lazily so schema-only consumers (API route
typing helpers, tests without GPU wheels) do not import ``torch`` eagerly.
"""

from __future__ import annotations

from typing import Any

from synthetic_data.behavioural_transformer.calibration import (
    ErrorCalibration,
    format_calibration_report,
    normalize_error,
)
from synthetic_data.behavioural_transformer.config import (
    DEFAULT_TRANSFORMER_CONFIG,
    TransformerConfig,
)
from synthetic_data.behavioural_transformer.schema import (
    BehaviourInferenceResult,
    SessionSequence,
)
from synthetic_data.behavioural_transformer.sequence_builder import (
    EventVocabulary,
    SequenceBuilder,
    synthesize_sequence_from_features,
)

__all__ = [
    "BehaviourInferenceResult",
    "BehaviourTransformer",
    "DEFAULT_TRANSFORMER_CONFIG",
    "ErrorCalibration",
    "EventVocabulary",
    "SequenceBuilder",
    "SessionSequence",
    "TrainedTransformerArtifact",
    "TransformerAnomalyModel",
    "TransformerConfig",
    "behaviour_insight_dict",
    "format_calibration_report",
    "infer_sessions",
    "load_trained_artifact",
    "normalize_error",
    "synthesize_sequence_from_features",
    "to_anomaly_prediction",
    "train_transformer",
]


def __getattr__(name: str) -> Any:
    """Lazy-load torch-backed modules on first attribute access."""
    if name in {
        "TransformerAnomalyModel",
        "behaviour_insight_dict",
        "infer_sessions",
        "to_anomaly_prediction",
    }:
        from synthetic_data.behavioural_transformer import inference as _inference

        return getattr(_inference, name)
    if name == "BehaviourTransformer":
        from synthetic_data.behavioural_transformer.model import BehaviourTransformer

        return BehaviourTransformer
    if name in {"TrainedTransformerArtifact", "load_trained_artifact", "train_transformer"}:
        from synthetic_data.behavioural_transformer import train as _train

        return getattr(_train, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
