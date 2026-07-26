"""Low-and-slow exfiltration across multiple days / weeks.

Injects small downloads on several active days for one employee — gradual
collection that builds over a campaign window rather than a single burst.
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from datetime import date, datetime, time, timedelta

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackRecord, AttackTarget, AttackType, Severity
from synthetic_data.attack_utils import employee_active_days
from synthetic_data.attacks._helpers import (
    advance,
    base_attack_metadata,
    find_day_login_session,
    insert_events,
    make_event_id_factory,
    validate_basic_target,
)
from synthetic_data.generators.event_factory import (
    FILE_ACCESS,
    FILE_DOWNLOAD,
    TimelineEvent,
)
from synthetic_data.models import BehaviorProfile, Employee

_DOWNLOAD_MB = (1, 2, 3, 4, 5)
_SENSITIVE = (
    "RES-FINANCE_DATABASE",
    "RES-PAYROLL",
    "RES-SOURCE_CODE_REPOSITORY",
    "RES-CLOUD_STORAGE",
    "RES-CRM",
)
_IP_PREFIXES = (34, 52, 13, 20, 44)
# Campaign length in calendar-active days (≈1–3 weeks of workdays).
_SPAN_DAYS = (5, 12)


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
    """Inject multi-day low-and-slow drips for one employee campaign."""
    _ = (employees, profiles)
    try:
        employee_events = [
            event for event in events if event.employee_id == target.employee_id
        ]
        if not validate_basic_target(
            employee_events, target, config, AttackType.LOW_AND_SLOW_EXFIL
        ):
            return events, None

        active_days = employee_active_days(events, target.employee_id)
        if not active_days:
            return events, None

        # Anchor the campaign at/near the selected target day, then extend forward.
        try:
            start_index = active_days.index(target.day)
        except ValueError:
            start_index = 0
        span = rng.randint(*_SPAN_DAYS)
        campaign_days = active_days[start_index : start_index + span]
        if len(campaign_days) < 3:
            # Fall back to the longest available forward window.
            campaign_days = active_days[max(0, len(active_days) - span) :]
        if len(campaign_days) < 2:
            campaign_days = list(active_days[: max(2, len(active_days))])
        if not campaign_days:
            return events, None

        confidence = rng.uniform(0.88, 0.98)
        source_ip = (
            f"{rng.choice(_IP_PREFIXES)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}"
        )
        id_factory = make_event_id_factory(events)
        generated: list[TimelineEvent] = []
        total_mb = 0.0
        drip_index = 0
        planned_drips = max(len(campaign_days), span)

        for day_offset, day in enumerate(campaign_days):
            day_target = AttackTarget(
                employee_id=target.employee_id,
                day=day,
                attack_type=target.attack_type,
                severity=target.severity,
                campaign_id=target.campaign_id,
            )
            picked = find_day_login_session(employee_events, day_target, rng)
            if picked is None:
                continue
            session_id, login_event, _day_events = picked

            # 1–2 small transfers per day, often late / off-hours.
            drips_today = 1 if day_offset % 3 else 2
            for _ in range(drips_today):
                drip_index += 1
                cursor = datetime.combine(
                    day,
                    time(hour=rng.randint(17, 21), minute=rng.randint(0, 50)),
                )
                if cursor <= login_event.timestamp:
                    cursor = login_event.timestamp + timedelta(
                        minutes=rng.randint(45, 180)
                    )
                # Long idle before each drip (low-and-slow cadence).
                cursor = advance(cursor, rng, low=1200, high=4200)
                size_mb = float(rng.choice(_DOWNLOAD_MB))
                total_mb += size_mb
                resource = rng.choice(_SENSITIVE)
                attack_session = f"{session_id}-SLOW-{drip_index}"

                for event_type, label in (
                    (FILE_ACCESS, "Low-and-Slow File Touch"),
                    (FILE_DOWNLOAD, "Low-and-Slow Multi-Day Drip"),
                ):
                    cursor = advance(cursor, rng, low=25, high=120)
                    day_target_for_meta = AttackTarget(
                        employee_id=target.employee_id,
                        day=day,
                        attack_type=AttackType.LOW_AND_SLOW_EXFIL,
                        severity=target.severity,
                        campaign_id=target.campaign_id,
                    )
                    generated.append(
                        TimelineEvent(
                            event_id=id_factory(),
                            employee_id=target.employee_id,
                            timestamp=cursor,
                            event_type=event_type,
                            device_id=login_event.device_id,
                            location_id=login_event.location_id,
                            session_id=attack_session,
                            resource_id=resource,
                            browser=login_event.browser,
                            operating_system=login_event.operating_system,
                            result="success",
                            metadata=base_attack_metadata(
                                attack_id=attack_id,
                                attack_type=AttackType.LOW_AND_SLOW_EXFIL,
                                stage_label=label,
                                stage_index=drip_index,
                                confidence=confidence,
                                target=day_target_for_meta,
                                source_ip=source_ip,
                                extra={
                                    "download_size_mb": size_mb,
                                    "mitre_tactic": "Exfiltration",
                                    "mitre_technique": "Data Transfer Size Limits",
                                    "low_and_slow": True,
                                    "drip_index": drip_index,
                                    "drip_total": planned_drips,
                                    "campaign_span_days": len(campaign_days),
                                    "campaign_start": campaign_days[0].isoformat(),
                                    "campaign_end": campaign_days[-1].isoformat(),
                                    "auth_method": "token",
                                    "command_sequence": [
                                        "stage_collection",
                                        "drip_exfil",
                                        resource,
                                    ],
                                    "device_fingerprint": (
                                        f"{login_event.device_id}|"
                                        f"{login_event.operating_system}|"
                                        f"{login_event.browser}"
                                    ),
                                    "entity_type": "user",
                                },
                            ),
                        )
                    )

        if len(generated) < 4:
            return events, None

        candidate = insert_events(events, generated)
        span_days = (campaign_days[-1] - campaign_days[0]).days + 1
        record = AttackRecord(
            attack_id=attack_id,
            employee_id=target.employee_id,
            attack_type=AttackType.LOW_AND_SLOW_EXFIL,
            severity=(
                target.severity
                if isinstance(target.severity, Severity)
                else Severity.MEDIUM
            ),
            day=campaign_days[0],
            description=(
                f"Low-and-slow exfiltration over {span_days} days "
                f"({len(campaign_days)} active days, {drip_index} drips, "
                f"{total_mb:.0f} MB total)."
            ),
            injected_event_ids=[event.event_id for event in generated],
            campaign_id=target.campaign_id,
        )
        return candidate, record
    except Exception:
        return events, None
