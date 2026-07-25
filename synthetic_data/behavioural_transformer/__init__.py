"""Transformer-based behavioural anomaly detection for SentinelAI.

Public API::

    from synthetic_data.behavioural_transformer import (
        SequenceBuilder,
        train_transformer,
        TransformerAnomalyModel,
        BehaviourTransformer,
    )
"""

from synthetic_data.behavioural_transformer.calibration import (
    ErrorCalibration,
    format_calibration_report,
    normalize_error,
)
from synthetic_data.behavioural_transformer.config import (
    DEFAULT_TRANSFORMER_CONFIG,
    TransformerConfig,
)
from synthetic_data.behavioural_transformer.inference import (
    TransformerAnomalyModel,
    behaviour_insight_dict,
    infer_sessions,
    to_anomaly_prediction,
)
from synthetic_data.behavioural_transformer.model import BehaviourTransformer
from synthetic_data.behavioural_transformer.schema import (
    BehaviourInferenceResult,
    SessionSequence,
)
from synthetic_data.behavioural_transformer.sequence_builder import (
    EventVocabulary,
    SequenceBuilder,
    synthesize_sequence_from_features,
)
from synthetic_data.behavioural_transformer.train import (
    TrainedTransformerArtifact,
    load_trained_artifact,
    train_transformer,
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
