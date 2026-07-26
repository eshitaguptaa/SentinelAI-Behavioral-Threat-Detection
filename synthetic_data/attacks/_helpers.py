"""Shared helpers for compact attack-technique injectors."""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackTarget, AttackType
from synthetic_data.attack_utils import event_simulation_date, find_sessions, sort_events
from synthetic_data.generators.event_factory import LOGIN, LOGOUT, TimelineEvent


def make_event_id_factory(events: Sequence[TimelineEvent]) -> Callable[[], str]:
    """Create a monotonic EVT-######## allocator based on existing IDs."""
    max_index = 0
    for event in events:
        if not event.event_id.startswith("EVT-"):
            continue
        suffix = event.event_id.split("-", maxsplit=1)[-1]
        if suffix.isdigit():
            max_index = max(max_index, int(suffix))

    state = {"value": max_index}

    def _next() -> str:
        state["value"] += 1
        return f"EVT-{state['value']:08d}"

    return _next


def insert_events(
    events: Sequence[TimelineEvent],
    attack_events: Sequence[TimelineEvent],
) -> list[TimelineEvent]:
    """Append attack events and return a chronologically sorted timeline."""
    combined = list(events)
    combined.extend(attack_events)
    return sort_events(combined)


def count_attack_type(
    employee_events: Sequence[TimelineEvent],
    attack_type: AttackType,
) -> int:
    """Count prior markers of a given attack type on an employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == attack_type.value
    )


def validate_basic_target(
    employee_events: Sequence[TimelineEvent],
    target: AttackTarget,
    config: AttackConfig,
    attack_type: AttackType,
) -> bool:
    """Shared eligibility: enough history, a LOGIN on the day, attack-cap OK."""
    if len(employee_events) < config.min_events_for_eligibility:
        return False
    if not any(event.event_type == LOGIN for event in employee_events):
        return False

    existing = count_attack_type(employee_events, attack_type)
    max_allowed = (
        config.max_attacks_per_employee
        if config.allow_multiple_attacks_per_employee
        else 1
    )
    if existing >= max_allowed:
        return False

    day_events = [
        event
        for event in employee_events
        if event_simulation_date(event) == target.day
    ]
    return any(event.event_type == LOGIN for event in day_events)


def find_day_login_session(
    employee_events: Sequence[TimelineEvent],
    target: AttackTarget,
    rng: random.Random,
) -> tuple[str, TimelineEvent, list[TimelineEvent]] | None:
    """Pick a LOGIN session on the target day; return (session_id, login, events)."""
    sessions = find_sessions(employee_events, employee_id=target.employee_id)
    candidates: list[tuple[str, TimelineEvent, list[TimelineEvent]]] = []

    for session_id, session_events in sessions.items():
        day_events = [
            event
            for event in session_events
            if event_simulation_date(event) == target.day
        ]
        login_event = next(
            (event for event in day_events if event.event_type == LOGIN),
            None,
        )
        if login_event is None:
            continue
        candidates.append((session_id, login_event, day_events))

    if not candidates:
        return None
    return rng.choice(candidates)


def advance(
    cursor: datetime,
    rng: random.Random,
    *,
    low: int,
    high: int,
) -> datetime:
    """Advance a cursor by a random number of seconds in ``[low, high]``."""
    return cursor + timedelta(seconds=rng.randint(low, high))


def base_attack_metadata(
    *,
    attack_id: str,
    attack_type: AttackType,
    stage_label: str,
    stage_index: int,
    confidence: float,
    target: AttackTarget,
    source_ip: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build common attack metadata keys expected by the feature extractors."""
    meta: dict[str, Any] = {
        "is_attack": True,
        "attack_id": attack_id,
        "attack_type": attack_type.value,
        "attack_stage": stage_index,
        "attack_stage_label": stage_label,
        "attack_confidence": confidence,
        "simulation_date": target.day.isoformat(),
        "source_ip": source_ip,
        "geo_location": "",
        "risk_indicators": [attack_type.value.lower()],
        # Hackathon brief schema keys (enriched further at export time).
        "entity_id": target.employee_id,
        "entity_type": "user",
        "auth_method": "password",
        "command_sequence": [stage_label],
    }
    if extra:
        meta.update(extra)
    if not meta.get("device_fingerprint"):
        meta["device_fingerprint"] = (
            f"{meta.get('attacker_device') or 'unknown'}|"
            f"{meta.get('attacker_os') or 'unknown'}|"
            f"{meta.get('attacker_browser') or 'unknown'}"
        )
    return meta
