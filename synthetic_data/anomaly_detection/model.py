"""Isolation Forest model wrapper and public anomaly-detection API.

Pipeline::

    FeatureVector → Preprocessing → Feature Matrix → IsolationForest
        → Raw Scores → Normalized Scores → AnomalyPrediction

Strictly unsupervised: consumes only ``FeatureVector.ml_features()``.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from synthetic_data.anomaly_detection.isolation_forest import (
    DEFAULT_RANDOM_STATE,
    build_isolation_forest,
    isolation_forest_params,
)
from synthetic_data.anomaly_detection.preprocessing import (
    FeatureVectorLike,
    build_feature_matrix,
    identities_from_vectors,
)
from synthetic_data.anomaly_detection.scoring import (
    AnomalyPrediction,
    ScoreNormalizer,
    build_anomaly_predictions,
)
from synthetic_data.anomaly_detection.validation import (
    AnomalyDetectionError,
    InvalidModelFileError,
    validate_feature_matrix,
    validate_model_fitted,
    validate_model_path_for_load,
    validate_model_path_for_save,
)

_MODEL_FILE_VERSION: int = 1


class IsolationForestModel:
    """Production wrapper around sklearn ``IsolationForest``.

    Stores fitted feature column order and score-normalisation statistics so
    predictions remain consistent across sessions.
    """

    def __init__(
        self,
        *,
        random_state: int = DEFAULT_RANDOM_STATE,
        **isolation_forest_overrides: Any,
    ) -> None:
        """Create an unfitted model.

        Args:
            random_state: Seed for deterministic tree construction.
            **isolation_forest_overrides: Forwarded to ``IsolationForest``
                (e.g. ``n_estimators``, ``contamination``, ``max_samples``).
        """
        overrides = dict(isolation_forest_overrides)
        overrides["random_state"] = random_state
        self._params = isolation_forest_params(**overrides)
        self._estimator = build_isolation_forest(**overrides)
        self._feature_names: tuple[str, ...] | None = None
        self._normalizer: ScoreNormalizer | None = None
        self._fitted: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_fitted(self) -> bool:
        """True after a successful ``fit()``."""
        return self._fitted

    @property
    def feature_names(self) -> tuple[str, ...] | None:
        """Behavioural feature column order learned at fit time."""
        return self._feature_names

    @property
    def n_features(self) -> int | None:
        """Number of behavioural features, or ``None`` if unfitted."""
        if self._feature_names is None:
            return None
        return len(self._feature_names)

    @property
    def params(self) -> dict[str, Any]:
        """Effective Isolation Forest hyperparameters."""
        return dict(self._params)

    @property
    def estimator(self) -> Any:
        """Underlying sklearn ``IsolationForest`` instance."""
        return self._estimator

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def fit(self, feature_vectors: Sequence[FeatureVectorLike]) -> IsolationForestModel:
        """Fit the Isolation Forest on behavioural features only.

        Args:
            feature_vectors: Phase 8 ``FeatureVector`` (or compatible) objects.

        Returns:
            ``self`` for chaining.
        """
        matrix, names = build_feature_matrix(feature_vectors)
        self._estimator.fit(matrix)
        self._feature_names = names

        # Fit normalizer on training decision scores (no label leakage).
        train_scores = self._estimator.decision_function(matrix)
        self._normalizer = ScoreNormalizer.from_decision_scores(train_scores)
        self._fitted = True
        return self

    def _require_ready(self) -> tuple[tuple[str, ...], ScoreNormalizer]:
        validate_model_fitted(self._fitted)
        if self._feature_names is None or self._normalizer is None:
            raise AnomalyDetectionError(
                "Model state incomplete after fit",
                code="model_not_fitted",
            )
        return self._feature_names, self._normalizer

    def _matrix_for(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> tuple[np.ndarray, list[tuple[str, str]]]:
        names, _ = self._require_ready()
        matrix, _ = build_feature_matrix(
            feature_vectors,
            feature_names=names,
        )
        validate_feature_matrix(
            matrix,
            feature_names=names,
            expected_n_features=len(names),
        )
        return matrix, identities_from_vectors(feature_vectors)

    def decision_function(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> np.ndarray:
        """Return raw sklearn decision scores (higher = more normal)."""
        matrix, _ = self._matrix_for(feature_vectors)
        return np.asarray(self._estimator.decision_function(matrix), dtype=np.float64)

    def score_samples(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> np.ndarray:
        """Return sklearn ``score_samples`` (higher = more normal)."""
        matrix, _ = self._matrix_for(feature_vectors)
        return np.asarray(self._estimator.score_samples(matrix), dtype=np.float64)

    def predict_labels(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> np.ndarray:
        """Return sklearn labels: ``-1`` anomaly, ``1`` normal."""
        matrix, _ = self._matrix_for(feature_vectors)
        return np.asarray(self._estimator.predict(matrix), dtype=np.int32)

    def predict(
        self,
        feature_vectors: Sequence[FeatureVectorLike],
    ) -> list[AnomalyPrediction]:
        """Batch-predict anomalies as ``AnomalyPrediction`` objects."""
        names, normalizer = self._require_ready()
        matrix, identities = self._matrix_for(feature_vectors)
        # Single estimator pass pair — sklearn predict + decision_function.
        raw_scores = np.asarray(
            self._estimator.decision_function(matrix),
            dtype=np.float64,
        )
        labels = np.asarray(self._estimator.predict(matrix), dtype=np.int32)
        return build_anomaly_predictions(
            identities=identities,
            raw_scores=raw_scores,
            predictions=labels,
            normalizer=normalizer,
        )

    def predict_one(self, feature_vector: FeatureVectorLike) -> AnomalyPrediction:
        """Predict for a single feature vector."""
        results = self.predict([feature_vector])
        return results[0]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        """Serialize the fitted model (estimator + feature order + normalizer)."""
        validate_model_fitted(self._fitted)
        target = validate_model_path_for_save(path)
        payload = {
            "version": _MODEL_FILE_VERSION,
            "params": self._params,
            "estimator": self._estimator,
            "feature_names": self._feature_names,
            "normalizer": self._normalizer,
            "fitted": self._fitted,
        }
        try:
            joblib.dump(payload, target)
        except Exception as exc:  # noqa: BLE001 — surface as domain error
            raise InvalidModelFileError(
                f"Failed to save model to {target}: {exc}"
            ) from exc
        return target

    @classmethod
    def load(cls, path: str | Path) -> IsolationForestModel:
        """Load a previously saved model from disk."""
        target = validate_model_path_for_load(path)
        try:
            payload = joblib.load(target)
        except Exception as exc:  # noqa: BLE001
            raise InvalidModelFileError(
                f"Failed to load model from {target}: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise InvalidModelFileError(
                f"Invalid model file format (expected dict): {target}"
            )
        if payload.get("version") != _MODEL_FILE_VERSION:
            raise InvalidModelFileError(
                f"Unsupported model file version: {payload.get('version')!r}"
            )
        required = ("params", "estimator", "feature_names", "normalizer", "fitted")
        missing = [key for key in required if key not in payload]
        if missing:
            raise InvalidModelFileError(
                f"Model file missing keys: {', '.join(missing)}"
            )
        if not payload["fitted"]:
            raise InvalidModelFileError("Saved model is not marked as fitted")

        model = cls.__new__(cls)
        model._params = dict(payload["params"])
        model._estimator = payload["estimator"]
        model._feature_names = tuple(payload["feature_names"])
        model._normalizer = payload["normalizer"]
        model._fitted = True
        return model


# Module-level active model used by the functional public API.
_active_model: IsolationForestModel | None = None


# ---------------------------------------------------------------------------
# Functional public API (active-model pattern)
# ---------------------------------------------------------------------------


def _require_active_model() -> IsolationForestModel:
    if _active_model is None:
        raise AnomalyDetectionError(
            "No active model. Call train_model() or load_model() first.",
            code="model_not_fitted",
        )
    validate_model_fitted(_active_model.is_fitted)
    return _active_model


def train_model(
    feature_vectors: Sequence[FeatureVectorLike],
    *,
    random_state: int = DEFAULT_RANDOM_STATE,
    **isolation_forest_overrides: Any,
) -> IsolationForestModel:
    """Train an Isolation Forest and set it as the active model.

    Args:
        feature_vectors: Phase 8 behavioural feature vectors.
        random_state: Deterministic seed.
        **isolation_forest_overrides: Optional sklearn hyperparameter overrides.

    Returns:
        The fitted ``IsolationForestModel`` (also stored as the active model).
    """
    global _active_model
    model = IsolationForestModel(
        random_state=random_state,
        **isolation_forest_overrides,
    )
    model.fit(feature_vectors)
    _active_model = model
    return model


def predict(
    feature_vectors: Sequence[FeatureVectorLike],
) -> list[AnomalyPrediction]:
    """Batch-predict using the active model."""
    return _require_active_model().predict(feature_vectors)


def predict_one(feature_vector: FeatureVectorLike) -> AnomalyPrediction:
    """Predict one vector using the active model."""
    return _require_active_model().predict_one(feature_vector)


def save_model(path: str | Path) -> Path:
    """Save the active fitted model to ``path``."""
    return _require_active_model().save(path)


def load_model(path: str | Path) -> IsolationForestModel:
    """Load a model from disk and set it as the active model."""
    global _active_model
    model = IsolationForestModel.load(path)
    _active_model = model
    return model


def get_active_model() -> IsolationForestModel | None:
    """Return the active model, or ``None`` if not trained/loaded."""
    return _active_model


def clear_active_model() -> None:
    """Clear the module-level active model (primarily for tests)."""
    global _active_model
    _active_model = None
