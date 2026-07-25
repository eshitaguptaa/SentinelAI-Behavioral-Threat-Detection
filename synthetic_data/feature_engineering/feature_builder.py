"""Public API for building employee-day feature vectors from timeline events.

This module orchestrates grouping, modular extraction, optional validation, and
deterministic ordering. It performs feature extraction only — no normalisation,
scaling, or model training.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from synthetic_data.feature_engineering.aggregation import (
    aggregate_all,
    aggregate_employee_day,
    group_events_by_employee_day,
    iter_sorted_group_keys,
)
from synthetic_data.feature_engineering.feature_extractors import (
    DEFAULT_EXTRACTORS,
    FeatureExtractor,
    TimelineEventLike,
    run_extractors,
)
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.feature_engineering.validation import (
    ValidationError,
    validate_extractor_outputs,
    validate_feature_vectors,
    validate_timestamps,
)


class FeatureBuildError(ValueError):
    """Raised when feature building fails validation in strict mode."""

    def __init__(self, message: str, errors: list[ValidationError]) -> None:
        super().__init__(message)
        self.errors = errors


def build_feature_vectors(
    events: Sequence[TimelineEventLike] | Iterable[TimelineEventLike],
    *,
    extractors: Sequence[FeatureExtractor] | None = None,
    derive_label: bool = True,
    validate: bool = True,
    strict: bool = False,
) -> list[FeatureVector]:
    """Convert timeline events into one ``FeatureVector`` per employee-day.

    Args:
        events: Timeline events from simulation / attack injection.
        extractors: Optional custom extractor pipeline (defaults to full set).
        derive_label: When True, set ``label`` from attack metadata indicators.
        validate: When True, run post-build validation checks.
        strict: When True with ``validate``, raise ``FeatureBuildError`` if any
            validation error is found.

    Returns:
        Deterministically ordered list of ``FeatureVector`` (by employee_id,
        then simulation_day).

    Notes:
        Designed for large corpora (1M+ events, 10k+ employees): grouping is a
        single O(n) pass; per-day work scales with that day's event count.
        No scaling / normalisation is applied.
    """
    if not isinstance(events, Sequence):
        event_list: list[TimelineEventLike] = list(events)
    else:
        event_list = list(events) if not isinstance(events, list) else events

    if not event_list:
        return []

    pipeline = extractors if extractors is not None else DEFAULT_EXTRACTORS
    vectors = aggregate_all(
        event_list,
        extractors=pipeline,
        derive_label=derive_label,
    )

    if validate:
        errors = validate_feature_vectors(vectors)
        if strict and errors:
            raise FeatureBuildError(
                f"Feature validation failed with {len(errors)} error(s)",
                errors,
            )
    return vectors


def build_feature_vectors_with_report(
    events: Sequence[TimelineEventLike] | Iterable[TimelineEventLike],
    *,
    extractors: Sequence[FeatureExtractor] | None = None,
    derive_label: bool = True,
    validate_source_timestamps: bool = False,
) -> tuple[list[FeatureVector], list[ValidationError]]:
    """Build feature vectors and always return accompanying validation errors.

    Optionally validates chronological timestamps inside each employee-day group
    before extraction (useful for debugging malformed timelines).
    """
    if not isinstance(events, Sequence):
        event_list = list(events)
    else:
        event_list = list(events) if not isinstance(events, list) else events

    errors: list[ValidationError] = []
    if not event_list:
        return [], errors

    pipeline = extractors if extractors is not None else DEFAULT_EXTRACTORS
    groups = group_events_by_employee_day(event_list)
    vectors: list[FeatureVector] = []

    for key in iter_sorted_group_keys(groups):
        employee_id, simulation_day = key
        day_events = groups[key]

        if validate_source_timestamps:
            errors.extend(
                validate_timestamps(
                    day_events,
                    employee_id=employee_id,
                    simulation_day=simulation_day,
                )
            )

        # Detect overlapping keys across extractors without changing outputs.
        per_extractor = [extractor.extract(day_events) for extractor in pipeline]
        errors.extend(
            validate_extractor_outputs(
                per_extractor,
                employee_id=employee_id,
                simulation_day=simulation_day,
            )
        )

        vectors.append(
            aggregate_employee_day(
                day_events,
                employee_id=employee_id,
                simulation_day=simulation_day,
                extractors=pipeline,
                derive_label=derive_label,
            )
        )

    errors.extend(validate_feature_vectors(vectors))
    return vectors, errors


def extract_features_for_day(
    events: Sequence[TimelineEventLike],
    *,
    extractors: Sequence[FeatureExtractor] | None = None,
) -> dict[str, int | float]:
    """Low-level helper: run extractors on a pre-grouped employee-day list."""
    pipeline = extractors if extractors is not None else DEFAULT_EXTRACTORS
    return run_extractors(events, pipeline)
