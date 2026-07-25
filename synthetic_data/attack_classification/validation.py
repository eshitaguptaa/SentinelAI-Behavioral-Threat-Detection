"""Validation for attack classification outputs."""

from __future__ import annotations

import math
from typing import Any, Protocol, runtime_checkable

from synthetic_data.attack_classification.schema import (
    VALID_ATTACK_TYPES,
    AttackClassification,
)


class AttackClassificationError(ValueError):
    """Raised when attack classification inputs/outputs are invalid."""

    def __init__(self, message: str, *, code: str = "attack_classification_error") -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class FeatureVectorLike(Protocol):
    """Minimal Phase 8 surface required by the classifier."""

    employee_id: str
    simulation_day: str

    def ml_features(self) -> dict[str, float]:
        ...


def _bad_number(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float):
        return math.isnan(value) or math.isinf(value)
    return False


def validate_classification(result: AttackClassification) -> None:
    """Validate a produced ``AttackClassification``."""
    if not result.employee_id or not isinstance(result.employee_id, str):
        raise AttackClassificationError(
            "employee_id must be a non-empty string",
            code="invalid_identity",
        )
    if not result.simulation_day or not isinstance(result.simulation_day, str):
        raise AttackClassificationError(
            "simulation_day must be a non-empty string",
            code="invalid_identity",
        )
    if result.attack_type not in VALID_ATTACK_TYPES:
        raise AttackClassificationError(
            f"Invalid attack_type: {result.attack_type!r}",
            code="invalid_attack_type",
        )
    if _bad_number(result.attack_confidence):
        raise AttackClassificationError(
            "attack_confidence must not be NaN/Inf",
            code="invalid_confidence",
        )
    conf = float(result.attack_confidence)
    if conf < 0.0 or conf > 1.0:
        raise AttackClassificationError(
            f"attack_confidence must be in [0, 1], got {conf}",
            code="invalid_confidence",
        )
    if not isinstance(result.matched_signals, list):
        raise AttackClassificationError(
            "matched_signals must be a list",
            code="invalid_signals",
        )
    for index, signal in enumerate(result.matched_signals):
        if not isinstance(signal, str) or not signal.strip():
            raise AttackClassificationError(
                f"matched_signals[{index}] must be a non-empty string",
                code="invalid_signals",
            )
