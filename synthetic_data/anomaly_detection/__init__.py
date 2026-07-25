"""Isolation Forest anomaly detection for SentinelAI (Phase 9).

Consumes Phase 8 ``FeatureVector`` objects and detects behavioural anomalies
using an unsupervised Isolation Forest. Evaluation-only / attack ground-truth
fields are never used — only ``FeatureVector.ml_features()``.

Public API::

    from synthetic_data.anomaly_detection import (
        train_model,
        predict,
        predict_one,
        save_model,
        load_model,
        AnomalyPrediction,
        IsolationForestModel,
    )

    model = train_model(feature_vectors)
    results = predict(feature_vectors)          # list[AnomalyPrediction]
    one = predict_one(feature_vectors[0])
    save_model("models/iforest.joblib")
    load_model("models/iforest.joblib")
"""

from synthetic_data.anomaly_detection.isolation_forest import (
    DEFAULT_BOOTSTRAP,
    DEFAULT_CONTAMINATION,
    DEFAULT_ISOLATION_FOREST_PARAMS,
    DEFAULT_MAX_SAMPLES,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_N_JOBS,
    DEFAULT_RANDOM_STATE,
    build_isolation_forest,
)
from synthetic_data.anomaly_detection.model import (
    IsolationForestModel,
    clear_active_model,
    get_active_model,
    load_model,
    predict,
    predict_one,
    save_model,
    train_model,
)
from synthetic_data.anomaly_detection.preprocessing import (
    FeatureVectorLike,
    build_feature_matrix,
)
from synthetic_data.anomaly_detection.scoring import (
    AnomalyPrediction,
    ScoreNormalizer,
)
from synthetic_data.anomaly_detection.validation import (
    AnomalyDetectionError,
    InvalidModelFileError,
    ModelNotFittedError,
)

__all__ = [
    "AnomalyDetectionError",
    "AnomalyPrediction",
    "DEFAULT_BOOTSTRAP",
    "DEFAULT_CONTAMINATION",
    "DEFAULT_ISOLATION_FOREST_PARAMS",
    "DEFAULT_MAX_SAMPLES",
    "DEFAULT_N_ESTIMATORS",
    "DEFAULT_N_JOBS",
    "DEFAULT_RANDOM_STATE",
    "FeatureVectorLike",
    "InvalidModelFileError",
    "IsolationForestModel",
    "ModelNotFittedError",
    "ScoreNormalizer",
    "build_feature_matrix",
    "build_isolation_forest",
    "clear_active_model",
    "get_active_model",
    "load_model",
    "predict",
    "predict_one",
    "save_model",
    "train_model",
]
