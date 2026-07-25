"""Aggregation helpers: group timeline events and merge feature dictionaries.

Grouping key is ``(employee_id, simulation_day)``. Simulation day is resolved
from ``metadata["simulation_date"]`` when present, otherwise from the event
timestamp date — matching Attack Injection Engine conventions.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime
from typing import Any

from synthetic_data.feature_engineering.feature_extractors import (
    DEFAULT_EXTRACTORS,
    FeatureDict,
    FeatureExtractor,
    TimelineEventLike,
    run_extractors,
)
from synthetic_data.feature_engineering.feature_schema import FEATURE_NAMES, FeatureVector

EmployeeDayKey = tuple[str, str]


def resolve_simulation_day(event: TimelineEventLike) -> str:
    """Return ISO simulation day string for an event.

    Prefers ``metadata["simulation_date"]`` (str or ``date``), else uses
    ``event.timestamp.date().isoformat()``.
    """
    meta = event.metadata or {}
    raw = meta.get("simulation_date")
    if isinstance(raw, str) and raw:
        # Normalise to ISO date when a datetime string is supplied.
        return raw[:10]
    if isinstance(raw, date) and not isinstance(raw, datetime):
        return raw.isoformat()
    if isinstance(raw, datetime):
        return raw.date().isoformat()
    return event.timestamp.date().isoformat()


def group_events_by_employee_day(
    events: Sequence[TimelineEventLike],
) -> dict[EmployeeDayKey, list[TimelineEventLike]]:
    """Group events by employee and simulation day in a single pass.

    Within each group, events are sorted by ``(timestamp, event_id)`` for
    deterministic temporal / session features.
    """
    groups: dict[EmployeeDayKey, list[TimelineEventLike]] = defaultdict(list)
    for event in events:
        key = (event.employee_id, resolve_simulation_day(event))
        groups[key].append(event)

    for key in groups:
        groups[key].sort(key=lambda e: (e.timestamp, e.event_id))
    return dict(groups)


def merge_feature_dicts(*dicts: Mapping[str, int | float]) -> FeatureDict:
    """Merge feature dictionaries left-to-right (later keys overwrite)."""
    merged: FeatureDict = {}
    for mapping in dicts:
        merged.update(mapping)
    return merged


def _derive_label(features: Mapping[str, int | float]) -> int:
    """Derive binary label from attack indicators when present."""
    has_attack = int(features.get("has_attack", 0) or 0)
    attack_events = int(features.get("attack_event_count", 0) or 0)
    return 1 if has_attack or attack_events > 0 else 0


def features_to_vector(
    *,
    employee_id: str,
    simulation_day: str,
    features: Mapping[str, int | float],
    label: int | None = None,
    derive_label: bool = True,
) -> FeatureVector:
    """Build a ``FeatureVector`` from a merged feature dictionary.

    Unknown keys are ignored. Missing schema fields keep their defaults.
    """
    payload: dict[str, Any] = {
        "employee_id": employee_id,
        "simulation_day": simulation_day,
    }
    for name in FEATURE_NAMES:
        if name in features:
            payload[name] = features[name]

    if label is not None:
        payload["label"] = label
    elif derive_label:
        payload["label"] = _derive_label(features)

    return FeatureVector(**payload)


def aggregate_employee_day(
    events: Sequence[TimelineEventLike],
    *,
    employee_id: str | None = None,
    simulation_day: str | None = None,
    extractors: Sequence[FeatureExtractor] | None = None,
    derive_label: bool = True,
) -> FeatureVector:
    """Extract and merge features for one employee-day event group."""
    if not events:
        raise ValueError("events must not be empty for aggregate_employee_day")

    eid = employee_id if employee_id is not None else events[0].employee_id
    day = simulation_day if simulation_day is not None else resolve_simulation_day(events[0])
    pipeline = extractors if extractors is not None else DEFAULT_EXTRACTORS
    features = run_extractors(events, pipeline)
    return features_to_vector(
        employee_id=eid,
        simulation_day=day,
        features=features,
        derive_label=derive_label,
    )


def iter_sorted_group_keys(
    groups: Mapping[EmployeeDayKey, Sequence[TimelineEventLike]],
) -> list[EmployeeDayKey]:
    """Return employee-day keys sorted for deterministic output order."""
    return sorted(groups.keys(), key=lambda item: (item[0], item[1]))


def aggregate_all(
    events: Sequence[TimelineEventLike] | Iterable[TimelineEventLike],
    *,
    extractors: Sequence[FeatureExtractor] | None = None,
    derive_label: bool = True,
) -> list[FeatureVector]:
    """Group all events and produce one ``FeatureVector`` per employee-day.

    Output order is sorted by ``(employee_id, simulation_day)`` for stability.
    """
    if not isinstance(events, Sequence):
        events = list(events)

    groups = group_events_by_employee_day(events)
    vectors: list[FeatureVector] = []
    for key in iter_sorted_group_keys(groups):
        employee_id, simulation_day = key
        vectors.append(
            aggregate_employee_day(
                groups[key],
                employee_id=employee_id,
                simulation_day=simulation_day,
                extractors=extractors,
                derive_label=derive_label,
            )
        )
    return vectors
