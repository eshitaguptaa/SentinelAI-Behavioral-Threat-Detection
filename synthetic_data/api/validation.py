"""Request validation helpers for the SentinelAI FastAPI layer.

Converts HTTP payloads into Phase 8 ``FeatureVector`` domain objects and
enforces batch / identity constraints. Does not retrain models or alter scores.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import fields
from typing import Any

from fastapi import HTTPException, status

from synthetic_data.api.schemas import FeatureVectorPayload, feature_payload_to_dict
from synthetic_data.feature_engineering.feature_schema import FeatureVector

_FEATURE_FIELD_NAMES: frozenset[str] = frozenset(f.name for f in fields(FeatureVector))


class ApiValidationError(ValueError):
    """Raised for semantically invalid API inputs (mapped to HTTP 400)."""

    def __init__(self, message: str, *, code: str = "validation_error") -> None:
        super().__init__(message)
        self.code = code


def build_feature_vector(payload: FeatureVectorPayload | Mapping[str, Any]) -> FeatureVector:
    """Construct a Phase 8 ``FeatureVector`` from a request payload.

    Unknown keys are ignored. Missing optional columns use dataclass defaults.
    Attack ground-truth columns may be present in the payload but are never
    used by Isolation Forest (``ml_features()`` excludes them).
    """
    raw = (
        feature_payload_to_dict(payload)
        if isinstance(payload, FeatureVectorPayload)
        else dict(payload)
    )

    employee_id = raw.get("employee_id")
    simulation_day = raw.get("simulation_day")
    if not isinstance(employee_id, str) or not employee_id.strip():
        raise ApiValidationError(
            "feature_vector.employee_id is required",
            code="missing_employee_id",
        )
    if not isinstance(simulation_day, str) or not simulation_day.strip():
        raise ApiValidationError(
            "feature_vector.simulation_day is required",
            code="missing_simulation_day",
        )

    kwargs: dict[str, Any] = {
        "employee_id": employee_id.strip(),
        "simulation_day": simulation_day.strip(),
    }
    for name, value in raw.items():
        if name in {"employee_id", "simulation_day"}:
            continue
        if name not in _FEATURE_FIELD_NAMES:
            continue
        if value is None and name == "label":
            kwargs[name] = None
            continue
        if value is None:
            continue
        kwargs[name] = value

    try:
        vector = FeatureVector(**kwargs)
    except TypeError as exc:
        raise ApiValidationError(
            f"Invalid feature_vector fields: {exc}",
            code="invalid_feature_vector",
        ) from exc

    # Ensure behavioural map is usable for the pipeline.
    try:
        features = vector.ml_features()
    except Exception as exc:  # noqa: BLE001 — surface as validation error
        raise ApiValidationError(
            f"feature_vector.ml_features() failed: {exc}",
            code="invalid_feature_vector",
        ) from exc
    if not features:
        raise ApiValidationError(
            "feature_vector produced an empty behavioural feature map",
            code="invalid_feature_vector",
        )
    return vector


def build_feature_vectors(
    payloads: Sequence[FeatureVectorPayload | Mapping[str, Any]],
) -> list[FeatureVector]:
    """Convert a batch of payloads; reject empty batches."""
    if not payloads:
        raise ApiValidationError(
            "feature_vectors must not be empty",
            code="empty_batch",
        )
    return [build_feature_vector(payload) for payload in payloads]


def require_fitted_model(model: Any) -> Any:
    """Raise HTTP 503 when the Isolation Forest model is unavailable."""
    if model is None or not getattr(model, "is_fitted", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Isolation Forest model is not loaded. Set SENTINELAI_MODEL_PATH "
                "to a fitted model file produced by Phase 9 save_model()."
            ),
        )
    return model
