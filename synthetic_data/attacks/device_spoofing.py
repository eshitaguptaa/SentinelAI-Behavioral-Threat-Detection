"""Device Spoofing attack technique.

Replays access from a mismatched device fingerprint (different OS / browser /
MAC-style device id) against an existing employee session day — classic
endpoint impersonation / stolen-session signal.
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
    DEVICE_CONNECT,
    FILE_ACCESS,
    LOGIN,
    LOGOUT,
    RESOURCE_ACCESS,
    TimelineEvent,
)
from synthetic_data.models import BehaviorProfile, Employee

_SPOOF_OS = ("Android 14", "Kali Linux", "Windows Server 2019", "ChromeOS")
_SPOOF_BROWSERS = ("Tor Browser", "Unknown", "HeadlessChrome", "curl/8.5")
_IP_PREFIXES = (185, 91, 45, 103, 194)


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
    """Inject a device-fingerprint mismatch burst for one employee/day."""
    _ = (employees, profiles)
    try:
        employee_events = [
            event for event in events if event.employee_id == target.employee_id
        ]
        if not validate_basic_target(
            employee_events, target, config, AttackType.DEVICE_SPOOFING
        ):
            return events, None

        picked = find_day_login_session(employee_events, target, rng)
        if picked is None:
            return events, None
        session_id, login_event, _day_events = picked

        confidence = rng.uniform(0.90, 0.99)
        spoof_device = f"DEV-SPOOF-{attack_id[-6:].upper()}"
        spoof_os = rng.choice(_SPOOF_OS)
        spoof_browser = rng.choice(_SPOOF_BROWSERS)
        source_ip = (
            f"{rng.choice(_IP_PREFIXES)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}"
        )
        # Start shortly after the legitimate login with a foreign fingerprint.
        cursor = login_event.timestamp + timedelta(minutes=rng.randint(15, 90))
        id_factory = make_event_id_factory(events)
        attack_session = f"{session_id}-SPOOF"

        stages: list[tuple[str, str | None, str]] = [
            (DEVICE_CONNECT, None, "Spoofed Device Connect"),
            (LOGIN, None, "Spoofed Login"),
            (RESOURCE_ACCESS, "RES-HR_PORTAL", "Spoofed Resource Access"),
            (APPLICATION_ACCESS, "RES-EMAIL", "Spoofed Mailbox Access"),
            (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Spoofed File Access"),
            (LOGOUT, None, "Spoofed Logout"),
        ]

        generated: list[TimelineEvent] = []
        for index, (event_type, resource_id, label) in enumerate(stages):
            cursor = advance(cursor, rng, low=40, high=160)
            generated.append(
                TimelineEvent(
                    event_id=id_factory(),
                    employee_id=target.employee_id,
                    timestamp=cursor,
                    event_type=event_type,
                    device_id=spoof_device,
                    location_id=login_event.location_id,
                    session_id=attack_session,
                    resource_id=resource_id,
                    browser=spoof_browser,
                    operating_system=spoof_os,
                    result="success",
                    metadata=base_attack_metadata(
                        attack_id=attack_id,
                        attack_type=AttackType.DEVICE_SPOOFING,
                        stage_label=label,
                        stage_index=index,
                        confidence=confidence,
                        target=target,
                        source_ip=source_ip,
        extra={
                            "attacker_device": spoof_device,
                            "attacker_browser": spoof_browser,
                            "attacker_os": spoof_os,
                            "fingerprint_mismatch": True,
                            "baseline_device": login_event.device_id,
                            "baseline_os": login_event.operating_system,
                            "mitre_tactic": "Initial Access",
                            "mitre_technique": "Hardware Additions",
                            "entity_type": "edge_device",
                            "auth_method": "certificate",
                            "device_fingerprint": (
                                f"{spoof_device}|{spoof_os}|{spoof_browser}|spoofed"
                            ),
                            "command_sequence": [
                                "spoof_device_connect",
                                "spoofed_login",
                                label,
                            ],
                        },
                    ),
                )
            )

        candidate = insert_events(events, generated)
        record = AttackRecord(
            attack_id=attack_id,
            employee_id=target.employee_id,
            attack_type=AttackType.DEVICE_SPOOFING,
            severity=target.severity if isinstance(target.severity, Severity) else Severity.HIGH,
            day=target.day,
            description=(
                f"Device spoofing: fingerprint {spoof_os}/{spoof_browser} "
                f"mismatched baseline device {login_event.device_id}."
            ),
            injected_event_ids=[event.event_id for event in generated],
            campaign_id=target.campaign_id,
        )
        return candidate, record
    except Exception:
        return events, None
