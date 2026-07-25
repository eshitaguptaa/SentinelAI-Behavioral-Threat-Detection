"""Feature engineering pipeline for SentinelAI timeline events.

Converts ``TimelineEvent`` streams into per-employee, per-simulation-day
``FeatureVector`` rows. Behavioural columns for Isolation Forest are exposed
via ``FeatureVector.ml_features()``; attack ground-truth columns remain on the
vector for evaluation / dashboards only. This package extracts features only —
it does not normalise, scale, or train models.
"""

from synthetic_data.feature_engineering.aggregation import (
    aggregate_all,
    aggregate_employee_day,
    group_events_by_employee_day,
    resolve_simulation_day,
)
from synthetic_data.feature_engineering.feature_builder import (
    FeatureBuildError,
    build_feature_vectors,
    build_feature_vectors_with_report,
    extract_features_for_day,
)
from synthetic_data.feature_engineering.feature_extractors import (
    DEFAULT_EXTRACTORS,
    AttackExtractor,
    AuthenticationExtractor,
    BehaviourExtractor,
    FeatureExtractor,
    FileActivityExtractor,
    IdentityExtractor,
    NetworkExtractor,
    ResourceExtractor,
    SessionExtractor,
    StatisticsExtractor,
    TemporalExtractor,
    TimelineEventLike,
    run_extractors,
)
from synthetic_data.feature_engineering.feature_schema import (
    ATTACK_FEATURE_NAMES,
    FEATURE_NAMES,
    IDENTITY_FIELD_NAMES,
    ML_FEATURE_NAMES,
    NEW_FEATURE_DOCS,
    NUM_FEATURES,
    NUM_ML_FEATURES,
    FeatureVector,
)
from synthetic_data.feature_engineering.validation import (
    ValidationError,
    validate_feature_vector,
    validate_feature_vectors,
    validate_ml_features,
)

__all__ = [
    "ATTACK_FEATURE_NAMES",
    "FEATURE_NAMES",
    "IDENTITY_FIELD_NAMES",
    "ML_FEATURE_NAMES",
    "NEW_FEATURE_DOCS",
    "NUM_FEATURES",
    "NUM_ML_FEATURES",
    "DEFAULT_EXTRACTORS",
    "AttackExtractor",
    "AuthenticationExtractor",
    "BehaviourExtractor",
    "FeatureBuildError",
    "FeatureExtractor",
    "FeatureVector",
    "FileActivityExtractor",
    "IdentityExtractor",
    "NetworkExtractor",
    "ResourceExtractor",
    "SessionExtractor",
    "StatisticsExtractor",
    "TemporalExtractor",
    "TimelineEventLike",
    "ValidationError",
    "aggregate_all",
    "aggregate_employee_day",
    "build_feature_vectors",
    "build_feature_vectors_with_report",
    "extract_features_for_day",
    "group_events_by_employee_day",
    "resolve_simulation_day",
    "run_extractors",
    "validate_feature_vector",
    "validate_feature_vectors",
    "validate_ml_features",
]
