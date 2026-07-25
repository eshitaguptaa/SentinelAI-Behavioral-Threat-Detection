"""Validation helpers for the Isolation Forest anomaly detection pipeline.

Raises clear ``AnomalyDetectionError`` exceptions. Never inspects attack labels
or evaluation-only ground-truth fields.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

# Identity / evaluation keys that must NEVER appear in ML feature dicts.
_FORBIDDEN_ML_KEYS: frozenset[str] = frozenset(
    {
        "employee_id",
        "simulation_day",
        "label",
        "has_attack",
        "attack_event_count",
        "attack_event_ratio",
        "unique_attack_type_count",
        "impossible_travel_count",
        "credential_theft_count",
        "privilege_escalation_count",
        "data_exfiltration_count",
        "after_hours_attack_count",
        "lateral_movement_count",
        "brute_force_count",
        "max_attack_confidence",
        "attack_type",
        "attack_confidence",
    }
)


class AnomalyDetectionError(ValueError):
    """Base error for anomaly detection validation / usage failures."""

    def __init__(self, message: str, *, code: str = "anomaly_error") -> None:
        super().__init__(message)
        self.code = code


class ModelNotFittedError(AnomalyDetectionError):
    """Raised when prediction is attempted before ``fit()``."""

    def __init__(self, message: str = "Model has not been fitted") -> None:
        super().__init__(message, code="model_not_fitted")


class InvalidModelFileError(AnomalyDetectionError):
    """Raised when a saved model file is missing or corrupt."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="invalid_model_file")


def validate_feature_vectors_nonempty(vectors: Sequence[Any]) -> None:
    """Ensure the input collection is non-empty."""
    if vectors is None:
        raise AnomalyDetectionError(
            "feature_vectors must not be None",
            code="empty_dataset",
        )
    if len(vectors) == 0:
        raise AnomalyDetectionError(
            "feature_vectors must not be empty",
            code="empty_dataset",
        )


def _is_bad_number(value: Any) -> bool:
    """True for None, NaN, or Inf."""
    if value is None:
        return True
    if isinstance(value, (float, np.floating)):
        return bool(math.isnan(float(value)) or math.isinf(float(value)))
    return False


def validate_ml_feature_dict(
    features: Mapping[str, Any],
    *,
    employee_id: str | None = None,
    required_names: Sequence[str] | None = None,
) -> None:
    """Validate one behavioural feature dictionary from ``ml_features()``."""
    if not isinstance(features, Mapping) or not features:
        raise AnomalyDetectionError(
            f"ml_features() returned empty/invalid mapping"
            + (f" for employee_id={employee_id!r}" if employee_id else ""),
            code="missing_features",
        )

    leaked = sorted(set(features.keys()) & _FORBIDDEN_ML_KEYS)
    if leaked:
        raise AnomalyDetectionError(
            "ml_features() must not contain identity/label/ground-truth keys: "
            + ", ".join(leaked),
            code="forbidden_features",
        )

    for name, value in features.items():
        if _is_bad_number(value):
            raise AnomalyDetectionError(
                f"Feature {name!r} is missing/NaN/Inf"
                + (f" (employee_id={employee_id!r})" if employee_id else ""),
                code="invalid_value",
            )

    if required_names is not None:
        missing = [name for name in required_names if name not in features]
        if missing:
            raise AnomalyDetectionError(
                "Missing behavioural features: " + ", ".join(missing[:20])
                + (f" … (+{len(missing) - 20} more)" if len(missing) > 20 else ""),
                code="missing_features",
            )
        # Extra keys are ignored by matrix builders; do not error.


def validate_feature_matrix(
    matrix: np.ndarray,
    *,
    feature_names: Sequence[str] | None = None,
    expected_n_features: int | None = None,
) -> None:
    """Validate a numerical feature matrix for Isolation Forest."""
    if not isinstance(matrix, np.ndarray):
        raise AnomalyDetectionError(
            "Feature matrix must be a numpy ndarray",
            code="invalid_matrix",
        )
    if matrix.ndim != 2:
        raise AnomalyDetectionError(
            f"Feature matrix must be 2-D, got shape {matrix.shape}",
            code="invalid_matrix",
        )
    if matrix.shape[0] == 0:
        raise AnomalyDetectionError(
            "Feature matrix has zero samples",
            code="empty_dataset",
        )
    if matrix.shape[1] == 0:
        raise AnomalyDetectionError(
            "Feature matrix has zero features",
            code="missing_features",
        )

    if feature_names is not None and len(feature_names) != matrix.shape[1]:
        raise AnomalyDetectionError(
            f"Feature name count ({len(feature_names)}) does not match "
            f"matrix width ({matrix.shape[1]})",
            code="dimension_mismatch",
        )

    if expected_n_features is not None and matrix.shape[1] != expected_n_features:
        raise AnomalyDetectionError(
            f"Feature dimension mismatch: expected {expected_n_features}, "
            f"got {matrix.shape[1]}",
            code="dimension_mismatch",
        )

    if not np.isfinite(matrix).all():
        bad = ~np.isfinite(matrix)
        n_bad = int(bad.sum())
        raise AnomalyDetectionError(
            f"Feature matrix contains {n_bad} NaN/Inf value(s)",
            code="invalid_value",
        )


def validate_model_fitted(fitted: bool) -> None:
    """Raise if the estimator has not been fitted."""
    if not fitted:
        raise ModelNotFittedError()


def validate_model_path_for_save(path: str | Path) -> Path:
    """Ensure the parent directory exists (or can be used) for saving."""
    target = Path(path)
    if target.exists() and target.is_dir():
        raise InvalidModelFileError(
            f"Model path is a directory, not a file: {target}"
        )
    parent = target.parent
    if parent and not parent.exists():
        raise InvalidModelFileError(
            f"Parent directory does not exist: {parent}"
        )
    return target


def validate_model_path_for_load(path: str | Path) -> Path:
    """Ensure a model file exists and is readable."""
    target = Path(path)
    if not target.exists():
        raise InvalidModelFileError(f"Model file not found: {target}")
    if not target.is_file():
        raise InvalidModelFileError(f"Model path is not a file: {target}")
    if target.stat().st_size == 0:
        raise InvalidModelFileError(f"Model file is empty: {target}")
    return target


def validate_score_arrays(
    *,
    raw_scores: np.ndarray,
    predictions: np.ndarray,
    n_samples: int,
) -> None:
    """Ensure score / prediction arrays align with sample count."""
    if len(raw_scores) != n_samples:
        raise AnomalyDetectionError(
            f"raw_scores length {len(raw_scores)} != n_samples {n_samples}",
            code="dimension_mismatch",
        )
    if len(predictions) != n_samples:
        raise AnomalyDetectionError(
            f"predictions length {len(predictions)} != n_samples {n_samples}",
            code="dimension_mismatch",
        )
    if not np.isfinite(raw_scores).all():
        raise AnomalyDetectionError(
            "raw_scores contain NaN/Inf",
            code="invalid_value",
        )
