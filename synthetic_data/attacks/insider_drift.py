"""Insider drift edge-case technique.

Simulates a legitimate employee slowly expanding their resource footprint
(new apps / files during business hours). Marked as an attack taxonomy entry
for evaluation, but intended as an ambiguous false-positive tuning case —
not a clear intrusion.
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from datetime import timedelta

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackRecord, AttackTarget, AttackType, Severity
from synthetic_data.attacks._helpers import (
    advance,
    base_attack_metadata,
    find_day_login_session,
    insert_events,
    make_event_id_factory,
    validate_basic_target,
)
from synthetic_data.generators.event_factory import (
    APPLICATION_ACCESS,
    FILE_ACCESS,
    RESOURCE_ACCESS,
    TimelineEvent,
)
from synthetic_data.models import BehaviorProfile, Employee

# Resources an expanding insider might "discover" over time.
_EXPANSION_RESOURCES: tuple[tuple[str, str], ...] = (
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE"),
    (APPLICATION_ACCESS, "RES-AZURE_PORTAL"),
    (RESOURCE_ACCESS, "RES-SECURITY_POLICIES"),
    (RESOURCE_ACCESS, "RES-HR_PORTAL"),
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY"),
    (RESOURCE_ACCESS, "RES-ANALYTICS"),
    (APPLICATION_ACCESS, "RES-JIRA"),
    (FILE_ACCESS, "RES-CRM"),
)
_IP_PREFIXES = (10, 172, 192)


def inject(
    events: list[TimelineEvent],
    target: AttackTarget,
    *,
    attack_id: str,
    config: AttackConfig,
    rng: random.Random,
    employees: Mapping[str, Employee] | None = None,
    profiles: Mapping[str, BehaviorProfile] | None = None,
) -> tuple[list[TimelineEvent], AttackRecord | None]:
    """Inject mild privilege/resource expansion during business hours."""
    _ = (employees, profiles)
    try:
        employee_events = [
            event for event in events if event.employee_id == target.employee_id
        ]
        if not validate_basic_target(
            employee_events, target, config, AttackType.INSIDER_DRIFT
        ):
            return events, None

        picked = find_day_login_session(employee_events, target, rng)
        if picked is None:
            return events, None
        session_id, login_event, _day_events = picked

        # Soft confidence — edge case, not a hard intrusion signature.
        confidence = rng.uniform(0.55, 0.75)
        source_ip = (
            f"{rng.choice(_IP_PREFIXES)}."
            f"{rng.randint(0, 254)}."
            f"{rng.randint(0, 254)}."
            f"{rng.randint(1, 254)}"
        )
        cursor = login_event.timestamp + timedelta(minutes=rng.randint(30, 120))
        id_factory = make_event_id_factory(events)
        picks = rng.sample(_EXPANSION_RESOURCES, k=rng.randint(3, 5))

        generated: list[TimelineEvent] = []
        for index, (event_type, resource_id) in enumerate(picks):
            cursor = advance(cursor, rng, low=180, high=600)
            # Keep inside typical business hours when possible.
            if cursor.hour >= 18:
                break
            generated.append(
                TimelineEvent(
                    event_id=id_factory(),
                    employee_id=target.employee_id,
                    timestamp=cursor,
                    event_type=event_type,
                    device_id=login_event.device_id,
                    location_id=login_event.location_id,
                    session_id=session_id,
                    resource_id=resource_id,
                    browser=login_event.browser,
                    operating_system=login_event.operating_system,
                    result="success",
                    metadata=base_attack_metadata(
                        attack_id=attack_id,
                        attack_type=AttackType.INSIDER_DRIFT,
                        stage_label="Resource Footprint Expansion",
                        stage_index=index,
                        confidence=confidence,
                        target=target,
                        source_ip=source_ip,
                        extra={
                            "edge_case": True,
                            "insider_drift": True,
                            "mitre_tactic": "Discovery",
                            "mitre_technique": "Cloud Service Discovery",
                        },
                    ),
                )
            )

        if len(generated) < 2:
            return events, None

        candidate = insert_events(events, generated)
        record = AttackRecord(
            attack_id=attack_id,
            employee_id=target.employee_id,
            attack_type=AttackType.INSIDER_DRIFT,
            severity=target.severity if isinstance(target.severity, Severity) else Severity.LOW,
            day=target.day,
            description=(
                "Insider drift edge case: gradual expansion into previously "
                "untouched resources during business hours."
            ),
            injected_event_ids=[event.event_id for event in generated],
            campaign_id=target.campaign_id,
        )
        return candidate, record
    except Exception:
        return events, None
