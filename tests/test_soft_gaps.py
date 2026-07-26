"""Tests for soft-gap hardening: schema, coverage, multi-day L&S, streaming."""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackType
from synthetic_data.attack_utils import choose_attack_targets
from synthetic_data.attacks import low_and_slow
from synthetic_data.generators.event_factory import (
    FILE_ACCESS,
    LOGIN,
    LOGOUT,
    TimelineEvent,
)
from synthetic_data.schema_brief import (
    enrich_event_metadata,
    to_access_log_records,
)
from synthetic_data.streaming import StreamingScorer


def _timeline(employee_id: str = "EMP-1", days: int = 10) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    idx = 1
    base = date(2024, 3, 1)
    for day_i in range(days):
        day = base + timedelta(days=day_i)
        # Skip weekends to mimic workdays.
        if day.weekday() >= 5:
            continue
        start = datetime.combine(day, datetime.min.time()).replace(hour=9)
        session = f"SES-{day_i}"
        for offset, etype in (
            (0, LOGIN),
            (30, FILE_ACCESS),
            (60, FILE_ACCESS),
            (120, LOGOUT),
        ):
            events.append(
                TimelineEvent(
                    event_id=f"EVT-{idx:08d}",
                    employee_id=employee_id,
                    timestamp=start + timedelta(minutes=offset),
                    event_type=etype,
                    device_id="DEV-1",
                    location_id="LOC-HQ",
                    session_id=session,
                    resource_id="RES-EMAIL" if etype == FILE_ACCESS else None,
                    browser="Chrome",
                    operating_system="Windows 11",
                    result="success",
                    metadata={"simulation_date": day.isoformat()},
                )
            )
            idx += 1
    return events


def test_schema_enrichment_and_access_log_fields() -> None:
    event = _timeline(days=1)[0]
    enrich_event_metadata(event)
    assert event.metadata["entity_type"] in {"user", "service_account", "edge_device"}
    assert event.metadata["auth_method"]
    assert event.metadata["device_fingerprint"]
    assert event.metadata["command_sequence"]
    assert event.metadata["source_ip"]

    rows = to_access_log_records([event])
    assert rows[0].entity_id == event.employee_id
    assert rows[0].label == "normal"
    assert rows[0].device_fingerprint


def test_attack_type_coverage_guaranteed() -> None:
    # Build a multi-employee timeline so every technique can be assigned.
    events: list[TimelineEvent] = []
    for i in range(1, 25):
        events.extend(_timeline(employee_id=f"EMP-{i:04d}", days=14))

    config = AttackConfig(
        attack_ratio=0.05,
        random_seed=7,
        allow_multiple_attacks_per_employee=False,
    )
    targets = choose_attack_targets(events, config, random.Random(7))
    covered = {target.attack_type for target in targets}
    assert AttackType.DEVICE_SPOOFING in covered
    assert AttackType.LOW_AND_SLOW_EXFIL in covered
    assert AttackType.INSIDER_DRIFT in covered
    assert covered == set(AttackType)


def test_low_and_slow_spans_multiple_days() -> None:
    events = _timeline(employee_id="EMP-9", days=21)
    from synthetic_data.attack_types import AttackTarget, Severity

    target = AttackTarget(
        employee_id="EMP-9",
        day=date(2024, 3, 4),
        attack_type=AttackType.LOW_AND_SLOW_EXFIL,
        severity=Severity.MEDIUM,
    )
    out, record = low_and_slow.inject(
        events,
        target,
        attack_id="ATK-SLOW",
        config=AttackConfig(),
        rng=random.Random(1),
    )
    assert record is not None
    assert "days" in record.description.lower() or "day" in record.description.lower()
    attack_days = {
        (event.metadata or {}).get("simulation_date")
        for event in out
        if (event.metadata or {}).get("attack_id") == "ATK-SLOW"
    }
    attack_days.discard(None)
    assert len(attack_days) >= 2


def test_streaming_scorer_flushes_windows() -> None:
    calls: list[int] = []

    def score_fn(window: list[TimelineEvent]) -> int:
        calls.append(len(window))
        return len(window)

    scorer = StreamingScorer(score_fn=score_fn, flush_every=3, max_buffer=20)
    events = _timeline(days=3)
    # Use first employee events only.
    results = scorer.on_events(events[:7])
    results.extend(scorer.flush_all())
    assert calls
    assert sum(calls) >= 3
