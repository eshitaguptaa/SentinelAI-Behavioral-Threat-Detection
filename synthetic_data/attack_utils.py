"""Utility helpers for the Attack Injection Engine.

These functions select targets, inspect timelines, and provide identifiers.
They intentionally do **not** mutate events or inject attacks.
"""

from __future__ import annotations

import csv
import random
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from typing import Any

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackTarget, AttackType, Severity
from synthetic_data.generators.event_factory import (
    APPLICATION_ACCESS,
    FILE_ACCESS,
    LOGIN,
    RESOURCE_ACCESS,
    TimelineEvent,
)

_RESOURCE_ACCESS_TYPES = frozenset(
    {
        APPLICATION_ACCESS,
        RESOURCE_ACCESS,
        FILE_ACCESS,
        "EMAIL_ACCESS",
    }
)


def generate_attack_id(index: int, *, prefix: str = "ATK") -> str:
    """Build a stable attack identifier from a monotonic index."""
    return f"{prefix}-{index:06d}"


def generate_campaign_id(index: int, *, prefix: str = "CAMP") -> str:
    """Build a stable campaign identifier from a monotonic index."""
    return f"{prefix}-{index:06d}"


def pick_random_employee(
    employee_ids: Sequence[str],
    rng: random.Random,
) -> str:
    """Return one employee ID chosen uniformly at random."""
    if not employee_ids:
        raise ValueError("employee_ids must not be empty")
    return rng.choice(list(employee_ids))


def sort_events(events: Sequence[TimelineEvent]) -> list[TimelineEvent]:
    """Return events ordered by timestamp, then event_id for stability."""
    return sorted(events, key=lambda event: (event.timestamp, event.event_id))


def find_login_events(
    events: Sequence[TimelineEvent],
    *,
    employee_id: str | None = None,
) -> list[TimelineEvent]:
    """Return LOGIN events, optionally filtered to one employee."""
    result: list[TimelineEvent] = []
    for event in events:
        if event.event_type != LOGIN:
            continue
        if employee_id is not None and event.employee_id != employee_id:
            continue
        result.append(event)
    return result


def find_resource_access_events(
    events: Sequence[TimelineEvent],
    *,
    employee_id: str | None = None,
) -> list[TimelineEvent]:
    """Return application/resource/file/email access events."""
    result: list[TimelineEvent] = []
    for event in events:
        if event.event_type not in _RESOURCE_ACCESS_TYPES:
            continue
        if employee_id is not None and event.employee_id != employee_id:
            continue
        result.append(event)
    return result


def find_sessions(
    events: Sequence[TimelineEvent],
    *,
    employee_id: str | None = None,
) -> dict[str, list[TimelineEvent]]:
    """Group events by ``session_id`` (optionally for one employee)."""
    sessions: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        if employee_id is not None and event.employee_id != employee_id:
            continue
        sessions[event.session_id].append(event)

    for session_id, session_events in sessions.items():
        sessions[session_id] = sort_events(session_events)
    return dict(sessions)


def events_by_employee(
    events: Sequence[TimelineEvent],
) -> dict[str, list[TimelineEvent]]:
    """Group timeline events by employee_id."""
    grouped: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        grouped[event.employee_id].append(event)
    for employee_id, employee_events in grouped.items():
        grouped[employee_id] = sort_events(employee_events)
    return dict(grouped)


def event_simulation_date(event: TimelineEvent) -> date:
    """Resolve the calendar day for an event from metadata or timestamp."""
    raw = (event.metadata or {}).get("simulation_date")
    if isinstance(raw, str) and raw:
        return date.fromisoformat(raw)
    if isinstance(raw, date):
        return raw
    return event.timestamp.date()


def employee_active_days(
    events: Sequence[TimelineEvent],
    employee_id: str,
) -> list[date]:
    """Return sorted unique simulation days with activity for an employee."""
    days = {
        event_simulation_date(event)
        for event in events
        if event.employee_id == employee_id
    }
    return sorted(days)


def eligible_employee_ids(
    events: Sequence[TimelineEvent],
    config: AttackConfig,
) -> list[str]:
    """Employees with enough timeline activity to be attack targets."""
    grouped = events_by_employee(events)
    eligible = [
        employee_id
        for employee_id, employee_events in grouped.items()
        if len(employee_events) >= config.min_events_for_eligibility
    ]
    return sorted(eligible)


def weighted_choice(
    items: Sequence[Any],
    weights: Sequence[float],
    rng: random.Random,
) -> Any:
    """Choose one item using the provided non-negative weights."""
    if not items:
        raise ValueError("items must not be empty")
    if len(items) != len(weights):
        raise ValueError("items and weights must be the same length")
    return rng.choices(list(items), weights=list(weights), k=1)[0]


def choose_severity(config: AttackConfig, rng: random.Random) -> Severity:
    """Sample a severity level from the configured distribution."""
    weights_map = config.normalized_severity_weights()
    severities = list(weights_map.keys())
    weights = [weights_map[severity] for severity in severities]
    return weighted_choice(severities, weights, rng)


def choose_attack_type(
    enabled_types: Sequence[AttackType],
    rng: random.Random,
) -> AttackType:
    """Sample an enabled attack type uniformly."""
    if not enabled_types:
        raise ValueError("enabled_types must not be empty")
    return rng.choice(list(enabled_types))


def choose_attack_targets(
    events: Sequence[TimelineEvent],
    config: AttackConfig,
    rng: random.Random,
) -> list[AttackTarget]:
    """Select employee/day/technique assignments for injection.

    Selection respects ``attack_ratio``, enabled types, severity mix,
    campaign probability, and the multiple-attacks-per-employee flag.
    This function does not mutate events.
    """
    eligible = eligible_employee_ids(events, config)
    if not eligible:
        return []

    enabled_types = config.resolve_enabled_types()
    if not enabled_types:
        return []

    target_count = max(1, int(round(len(eligible) * config.attack_ratio)))
    target_count = min(target_count, len(eligible))
    selected_employees = rng.sample(eligible, k=target_count)

    targets: list[AttackTarget] = []
    campaign_index = 1

    for employee_id in selected_employees:
        active_days = employee_active_days(events, employee_id)
        if not active_days:
            continue

        attack_slots = 1
        if config.allow_multiple_attacks_per_employee:
            attack_slots = rng.randint(1, max(1, config.max_attacks_per_employee))

        use_campaign = rng.random() < config.campaign_probability and attack_slots > 1
        campaign_id = (
            generate_campaign_id(campaign_index) if use_campaign else None
        )
        if use_campaign:
            campaign_index += 1

        # Prefer distinct days when assigning multiple techniques.
        day_pool = list(active_days)
        rng.shuffle(day_pool)

        for slot in range(attack_slots):
            day = day_pool[slot % len(day_pool)]
            attack_type = choose_attack_type(enabled_types, rng)
            severity = choose_severity(config, rng)
            targets.append(
                AttackTarget(
                    employee_id=employee_id,
                    day=day,
                    attack_type=attack_type,
                    severity=severity,
                    campaign_id=campaign_id,
                )
            )

            if not config.allow_multiple_attacks_per_employee:
                break

    return targets


def load_events_from_csv(path: str | Path) -> list[TimelineEvent]:
    """Load timeline events previously exported to ``events.csv``."""
    csv_path = Path(path)
    events: list[TimelineEvent] = []

    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            timestamp_raw = row.get("timestamp", "").strip()
            timestamp = datetime.fromisoformat(timestamp_raw)

            metadata: dict[str, Any] = {}
            work_mode = (row.get("work_mode") or "").strip()
            simulation_date = (row.get("simulation_date") or "").strip()
            if work_mode:
                metadata["work_mode"] = work_mode
            if simulation_date:
                metadata["simulation_date"] = simulation_date

            events.append(
                TimelineEvent(
                    event_id=(row.get("event_id") or f"EVT-{index:08d}").strip(),
                    employee_id=(row.get("employee_id") or "").strip(),
                    timestamp=timestamp,
                    event_type=(row.get("event_type") or "").strip(),
                    device_id=(row.get("device_id") or "").strip(),
                    location_id=(row.get("location_id") or "").strip(),
                    session_id=(row.get("session_id") or "").strip(),
                    resource_id=(row.get("resource_id") or None) or None,
                    browser=(row.get("browser") or None) or None,
                    operating_system=(row.get("operating_system") or None) or None,
                    result=(row.get("result") or "success").strip() or "success",
                    metadata=metadata,
                )
            )

    return sort_events(events)


def ensure_timeline_consistency(events: Sequence[TimelineEvent]) -> list[TimelineEvent]:
    """Return a chronologically sorted copy of the event stream."""
    return sort_events(events)


def count_by_key(values: Iterable[str]) -> dict[str, int]:
    """Count occurrences of string keys."""
    counts: dict[str, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return dict(sorted(counts.items()))
