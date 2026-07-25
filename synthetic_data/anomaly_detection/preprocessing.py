"""Preprocessing: FeatureVector → behavioural feature matrix.

Extracts ONLY ``FeatureVector.ml_features()`` (Phase 8 behavioural columns).
Does not scale, normalise, encode, or engineer features.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

import numpy as np

from synthetic_data.anomaly_detection.validation import (
    AnomalyDetectionError,
    validate_feature_matrix,
    validate_feature_vectors_nonempty,
    validate_ml_feature_dict,
)
from synthetic_data.feature_engineering.feature_schema import ML_FEATURE_NAMES


@runtime_checkable
class FeatureVectorLike(Protocol):
    """Minimal Phase 8 vector surface required by anomaly detection."""

    employee_id: str
    simulation_day: str

    def ml_features(self) -> dict[str, float]:
        """Return behavioural features only (no identity / ground truth)."""


def resolve_feature_names(
    vectors: Sequence[FeatureVectorLike],
    *,
    expected_names: Sequence[str] | None = None,
) -> tuple[str, ...]:
    """Return stable behavioural feature column order.

    Prefers the Phase 8 canonical ``ML_FEATURE_NAMES`` order when present in
    the vector's ``ml_features()`` keys. Falls back to sorted keys only when
    the canonical list is unavailable (should not happen in production).
    """
    validate_feature_vectors_nonempty(vectors)
    sample = vectors[0].ml_features()
    validate_ml_feature_dict(sample, employee_id=vectors[0].employee_id)

    if expected_names is not None:
        names = tuple(expected_names)
    else:
        # Preserve Phase 8 ordering; append any unexpected extras deterministically.
        present = set(sample.keys())
        ordered = [name for name in ML_FEATURE_NAMES if name in present]
        extras = sorted(present - set(ordered))
        names = tuple(ordered + extras)

    if not names:
        raise AnomalyDetectionError(
            "No behavioural features found in ml_features()",
            code="empty_features",
        )
    return names


def extract_ml_feature_row(
    vector: FeatureVectorLike,
    feature_names: Sequence[str],
) -> list[float]:
    """Extract one row of behavioural features in ``feature_names`` order."""
    features = vector.ml_features()
    validate_ml_feature_dict(
        features,
        employee_id=getattr(vector, "employee_id", None),
        required_names=feature_names,
    )
    return [float(features[name]) for name in feature_names]


def build_feature_matrix(
    vectors: Sequence[FeatureVectorLike],
    *,
    feature_names: Sequence[str] | None = None,
) -> tuple[np.ndarray, tuple[str, ...]]:
    """Build a dense ``(n_samples, n_features)`` float64 matrix.

    Returns:
        ``(matrix, feature_names)`` with rows aligned to ``vectors`` order and
        columns in stable behavioural feature order.

    Raises:
        AnomalyDetectionError: on empty input, missing features, NaN/Inf, or
        inconsistent dimensions.
    """
    validate_feature_vectors_nonempty(vectors)
    names = resolve_feature_names(vectors, expected_names=feature_names)

    # Pre-allocate to avoid repeated list growth on large corpora (100k+).
    n_samples = len(vectors)
    n_features = len(names)
    matrix = np.empty((n_samples, n_features), dtype=np.float64)

    for row_index, vector in enumerate(vectors):
        row = extract_ml_feature_row(vector, names)
        matrix[row_index, :] = row

    validate_feature_matrix(matrix, feature_names=names)
    return matrix, names


def identities_from_vectors(
    vectors: Sequence[FeatureVectorLike],
) -> list[tuple[str, str]]:
    """Return ``(employee_id, simulation_day)`` pairs aligned to ``vectors``."""
    return [(v.employee_id, v.simulation_day) for v in vectors]


def matrix_summary(matrix: np.ndarray) -> dict[str, Any]:
    """Lightweight diagnostics for logging / debugging (not used in training)."""
    return {
        "n_samples": int(matrix.shape[0]),
        "n_features": int(matrix.shape[1]) if matrix.ndim == 2 else 0,
        "dtype": str(matrix.dtype),
    }
