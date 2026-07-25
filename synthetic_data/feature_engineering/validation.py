"""Validation helpers for extracted feature vectors.

Checks cover missing / NaN values, duplicate feature keys during merges,
invalid timestamps on source events, nonsensical counts, entropy / login-hour
bounds, and Isolation Forest input hygiene (``ml_features()`` must never leak
identity or attack ground truth).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from synthetic_data.feature_engineering.feature_extractors import TimelineEventLike
from synthetic_data.feature_engineering.feature_schema import (
    ATTACK_FEATURE_NAMES,
    FEATURE_NAMES,
    IDENTITY_FIELD_NAMES,
    ML_FEATURE_NAMES,
    FeatureVector,
)

# Count fields that must be non-negative integers (or integral floats).
_NON_NEGATIVE_COUNT_FIELDS: frozenset[str] = frozenset(
    {
        "total_events",
        "login_count",
        "logout_count",
        "application_access_count",
        "resource_access_count",
        "email_access_count",
        "meeting_join_count",
        "break_start_count",
        "device_connect_count",
        "unique_event_type_count",
        "unique_device_count",
        "unique_location_count",
        "unique_browser_count",
        "unique_os_count",
        "unique_resource_count",
        "resource_touch_count",
        "sensitive_resource_count",
        "resource_switch_count",
        "auth_success_count",
        "auth_failure_count",
        "max_failed_login_streak",
        "vpn_connect_count",
        "vpn_disconnect_count",
        "location_change_count",
        "country_change_count",
        "remote_event_count",
        "unique_source_ip_count",
        "cross_location_session_count",
        "file_access_count",
        "mass_download_event_count",
        "attack_event_count",
        "unique_attack_type_count",
        "has_attack",
        "impossible_travel_count",
        "credential_theft_count",
        "privilege_escalation_count",
        "data_exfiltration_count",
        "after_hours_attack_count",
        "lateral_movement_count",
        "brute_force_count",
        "burst_max_5min",
        "after_hours_event_count",
        "night_event_count",
        "is_weekend",
        "unique_active_hour_count",
        "session_count",
        "multi_device_session_count",
    }
)

_RATIO_FIELDS: frozenset[str] = frozenset(
    {
        "auth_failure_rate",
        "vpn_usage_ratio",
        "file_access_ratio",
        "attack_event_ratio",
    }
)

_ENTROPY_FIELDS: frozenset[str] = frozenset(
    {
        "event_type_entropy",
        "resource_entropy",
        "device_entropy",
    }
)

_LOGIN_HOUR_FIELDS: frozenset[str] = frozenset(
    {
        "mean_login_hour",
        "median_login_hour",
        "std_login_hour",
        "first_event_hour",
        "last_event_hour",
    }
)

_IDLE_GAP_FIELDS: frozenset[str] = frozenset(
    {
        "max_idle_gap_sec",
        "median_idle_gap_sec",
        "inter_event_mean_sec",
        "inter_event_std_sec",
    }
)


@dataclass(slots=True)
class ValidationError:
    """A single validation finding for a feature vector or source event."""

    code: str
    message: str
    employee_id: str | None = None
    simulation_day: str | None = None
    field: str | None = None
    value: Any = None


def _is_nan(value: Any) -> bool:
    """True for float NaN values."""
    return isinstance(value, float) and math.isnan(value)


def _is_inf(value: Any) -> bool:
    """True for float ±Inf values."""
    return isinstance(value, float) and math.isinf(value)


def find_duplicate_keys(*dicts: Mapping[str, Any]) -> list[str]:
    """Return keys that appear in more than one mapping (pairwise overlaps)."""
    seen: set[str] = set()
    duplicates: set[str] = set()
    for mapping in dicts:
        for key in mapping:
            if key in seen:
                duplicates.add(key)
            else:
                seen.add(key)
    return sorted(duplicates)


def validate_timestamps(
    events: Sequence[TimelineEventLike],
    *,
    employee_id: str | None = None,
    simulation_day: str | None = None,
) -> list[ValidationError]:
    """Validate that every event has a usable ``datetime`` timestamp."""
    errors: list[ValidationError] = []
    previous: datetime | None = None

    for index, event in enumerate(events):
        ts = event.timestamp
        eid = employee_id or event.employee_id
        if not isinstance(ts, datetime):
            errors.append(
                ValidationError(
                    code="invalid_timestamp",
                    message=f"Event at index {index} has non-datetime timestamp",
                    employee_id=eid,
                    simulation_day=simulation_day,
                    field="timestamp",
                    value=ts,
                )
            )
            continue
        # Naive and aware are both accepted; reject clearly broken years.
        if ts.year < 1970 or ts.year > 2100:
            errors.append(
                ValidationError(
                    code="invalid_timestamp",
                    message=f"Event at index {index} timestamp year out of range: {ts.year}",
                    employee_id=eid,
                    simulation_day=simulation_day,
                    field="timestamp",
                    value=ts,
                )
            )
        if previous is not None and ts < previous:
            errors.append(
                ValidationError(
                    code="timestamp_order",
                    message=f"Event at index {index} is out of chronological order",
                    employee_id=eid,
                    simulation_day=simulation_day,
                    field="timestamp",
                    value=ts,
                )
            )
        previous = ts
    return errors


def validate_feature_dict(
    features: Mapping[str, Any],
    *,
    employee_id: str | None = None,
    simulation_day: str | None = None,
    require_all_features: bool = False,
) -> list[ValidationError]:
    """Validate a raw feature dictionary before / after merging extractors."""
    errors: list[ValidationError] = []

    for name, value in features.items():
        if value is None:
            errors.append(
                ValidationError(
                    code="missing_value",
                    message=f"Feature '{name}' is None",
                    employee_id=employee_id,
                    simulation_day=simulation_day,
                    field=name,
                    value=value,
                )
            )
            continue
        if _is_nan(value):
            errors.append(
                ValidationError(
                    code="nan_value",
                    message=f"Feature '{name}' is NaN",
                    employee_id=employee_id,
                    simulation_day=simulation_day,
                    field=name,
                    value=value,
                )
            )
        if _is_inf(value):
            errors.append(
                ValidationError(
                    code="inf_value",
                    message=f"Feature '{name}' is Inf",
                    employee_id=employee_id,
                    simulation_day=simulation_day,
                    field=name,
                    value=value,
                )
            )

    if require_all_features:
        for name in FEATURE_NAMES:
            if name not in features:
                errors.append(
                    ValidationError(
                        code="missing_feature",
                        message=f"Required feature '{name}' is absent",
                        employee_id=employee_id,
                        simulation_day=simulation_day,
                        field=name,
                    )
                )

    return errors


def validate_ml_features(vector: FeatureVector) -> list[ValidationError]:
    """Ensure ``ml_features()`` contains only behavioural Isolation Forest inputs.

    Rejects identity fields, labels, and attack ground-truth columns.
    """
    errors: list[ValidationError] = []
    eid = vector.employee_id
    day = vector.simulation_day
    ml = vector.ml_features()
    forbidden = IDENTITY_FIELD_NAMES | ATTACK_FEATURE_NAMES

    for key in ml:
        if key in forbidden:
            errors.append(
                ValidationError(
                    code="ml_features_leak",
                    message=(
                        f"ml_features() must not contain identity/label/ground-truth "
                        f"field '{key}'"
                    ),
                    employee_id=eid,
                    simulation_day=day,
                    field=key,
                    value=ml[key],
                )
            )
        if key not in ML_FEATURE_NAMES:
            errors.append(
                ValidationError(
                    code="ml_features_unknown",
                    message=f"ml_features() contains unexpected key '{key}'",
                    employee_id=eid,
                    simulation_day=day,
                    field=key,
                    value=ml[key],
                )
            )

    missing = [name for name in ML_FEATURE_NAMES if name not in ml]
    for name in missing:
        errors.append(
            ValidationError(
                code="ml_features_missing",
                message=f"ml_features() missing behavioural feature '{name}'",
                employee_id=eid,
                simulation_day=day,
                field=name,
            )
        )

    return errors


def validate_feature_vector(vector: FeatureVector) -> list[ValidationError]:
    """Validate a fully constructed ``FeatureVector`` instance."""
    errors: list[ValidationError] = []
    eid = vector.employee_id
    day = vector.simulation_day

    if not eid or not isinstance(eid, str):
        errors.append(
            ValidationError(
                code="invalid_identity",
                message="employee_id must be a non-empty string",
                employee_id=eid,
                simulation_day=day,
                field="employee_id",
                value=eid,
            )
        )
    if not day or not isinstance(day, str):
        errors.append(
            ValidationError(
                code="invalid_identity",
                message="simulation_day must be a non-empty ISO date string",
                employee_id=eid,
                simulation_day=day,
                field="simulation_day",
                value=day,
            )
        )
    elif len(day) < 10:
        errors.append(
            ValidationError(
                code="invalid_identity",
                message="simulation_day looks malformed",
                employee_id=eid,
                simulation_day=day,
                field="simulation_day",
                value=day,
            )
        )

    if vector.label is not None and vector.label not in (0, 1):
        errors.append(
            ValidationError(
                code="invalid_label",
                message="label must be 0, 1, or None",
                employee_id=eid,
                simulation_day=day,
                field="label",
                value=vector.label,
            )
        )

    data = vector.to_dict()
    for name in FEATURE_NAMES:
        value = data.get(name)
        if value is None:
            errors.append(
                ValidationError(
                    code="missing_value",
                    message=f"Feature '{name}' is None",
                    employee_id=eid,
                    simulation_day=day,
                    field=name,
                    value=value,
                )
            )
            continue
        if _is_nan(value):
            errors.append(
                ValidationError(
                    code="nan_value",
                    message=f"Feature '{name}' is NaN",
                    employee_id=eid,
                    simulation_day=day,
                    field=name,
                    value=value,
                )
            )
        if _is_inf(value):
            errors.append(
                ValidationError(
                    code="inf_value",
                    message=f"Feature '{name}' is Inf",
                    employee_id=eid,
                    simulation_day=day,
                    field=name,
                    value=value,
                )
            )

        if name in _NON_NEGATIVE_COUNT_FIELDS:
            if isinstance(value, float) and not value.is_integer():
                errors.append(
                    ValidationError(
                        code="invalid_count",
                        message=f"Count feature '{name}' is not an integer value",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )
            if isinstance(value, (int, float)) and value < 0:
                errors.append(
                    ValidationError(
                        code="invalid_count",
                        message=f"Count feature '{name}' is negative",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

        if name in _RATIO_FIELDS and isinstance(value, (int, float)):
            if value < 0.0 or value > 1.0:
                errors.append(
                    ValidationError(
                        code="invalid_ratio",
                        message=f"Ratio feature '{name}' outside [0, 1]",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

        if name in _ENTROPY_FIELDS and isinstance(value, (int, float)):
            if value < 0.0:
                errors.append(
                    ValidationError(
                        code="invalid_entropy",
                        message=f"Entropy feature '{name}' must be >= 0",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

        if name in _LOGIN_HOUR_FIELDS and isinstance(value, (int, float)):
            # std_login_hour can exceed 24 theoretically but is typically small;
            # mean/median/first/last must sit in [0, 24].
            if name == "std_login_hour":
                if value < 0.0:
                    errors.append(
                        ValidationError(
                            code="invalid_temporal",
                            message="std_login_hour must be >= 0",
                            employee_id=eid,
                            simulation_day=day,
                            field=name,
                            value=value,
                        )
                    )
            elif value < 0.0 or value > 24.0:
                errors.append(
                    ValidationError(
                        code="invalid_temporal",
                        message=f"Hour feature '{name}' outside [0, 24]",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

        if name in _IDLE_GAP_FIELDS and isinstance(value, (int, float)):
            if value < 0.0:
                errors.append(
                    ValidationError(
                        code="invalid_idle_gap",
                        message=f"Idle/gap feature '{name}' must be >= 0",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

        if name == "weekday" and isinstance(value, (int, float)):
            if value < 0 or value > 6:
                errors.append(
                    ValidationError(
                        code="invalid_count",
                        message="weekday must be in [0, 6]",
                        employee_id=eid,
                        simulation_day=day,
                        field=name,
                        value=value,
                    )
                )

    # Consistency: attack flags vs counts.
    if vector.has_attack == 1 and vector.attack_event_count <= 0:
        errors.append(
            ValidationError(
                code="inconsistent_attack",
                message="has_attack=1 but attack_event_count=0",
                employee_id=eid,
                simulation_day=day,
                field="has_attack",
                value=vector.has_attack,
            )
        )
    if vector.attack_event_count > 0 and vector.total_events > 0:
        if vector.attack_event_count > vector.total_events:
            errors.append(
                ValidationError(
                    code="invalid_count",
                    message="attack_event_count exceeds total_events",
                    employee_id=eid,
                    simulation_day=day,
                    field="attack_event_count",
                    value=vector.attack_event_count,
                )
            )

    errors.extend(validate_ml_features(vector))
    return errors


def validate_feature_vectors(
    vectors: Sequence[FeatureVector],
) -> list[ValidationError]:
    """Validate a collection of feature vectors; also flag duplicate rows."""
    errors: list[ValidationError] = []
    seen: set[tuple[str, str]] = set()

    for vector in vectors:
        errors.extend(validate_feature_vector(vector))
        key = (vector.employee_id, vector.simulation_day)
        if key in seen:
            errors.append(
                ValidationError(
                    code="duplicate_feature_vector",
                    message="Duplicate FeatureVector for employee/day",
                    employee_id=vector.employee_id,
                    simulation_day=vector.simulation_day,
                )
            )
        else:
            seen.add(key)
    return errors


def validate_extractor_outputs(
    extractor_dicts: Sequence[Mapping[str, Any]],
    *,
    employee_id: str | None = None,
    simulation_day: str | None = None,
) -> list[ValidationError]:
    """Validate extractor outputs for NaNs and overlapping (duplicate) keys."""
    errors: list[ValidationError] = []
    duplicates = find_duplicate_keys(*extractor_dicts)
    for key in duplicates:
        errors.append(
            ValidationError(
                code="duplicate_feature",
                message=f"Feature key '{key}' produced by multiple extractors",
                employee_id=employee_id,
                simulation_day=simulation_day,
                field=key,
            )
        )
    for mapping in extractor_dicts:
        errors.extend(
            validate_feature_dict(
                mapping,
                employee_id=employee_id,
                simulation_day=simulation_day,
            )
        )
    return errors


def has_errors(errors: Iterable[ValidationError]) -> bool:
    """Convenience: True when the error iterable is non-empty."""
    return any(True for _ in errors)
