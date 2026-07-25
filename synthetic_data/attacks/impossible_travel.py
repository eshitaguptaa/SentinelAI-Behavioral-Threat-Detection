"""Impossible Travel attack technique.

Injects a geographically implausible remote compromise into one existing
employee session: a second access burst from another country appears only
minutes after a legitimate login.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_types import AttackRecord, AttackTarget, AttackType, Severity
from synthetic_data.attack_utils import event_simulation_date, find_sessions, sort_events
from synthetic_data.generators.event_factory import (
    APPLICATION_ACCESS,
    FILE_ACCESS,
    LOGIN,
    LOGOUT,
    RESOURCE_ACCESS,
    TimelineEvent,
    VPN_CONNECT,
)
from synthetic_data.models import BehaviorProfile, Employee

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_TRAVEL_GAP_MINUTES: Final[int] = 10
MAX_TRAVEL_GAP_MINUTES: Final[int] = 30
# Flights between distant countries cannot realistically complete this fast.
MIN_REALISTIC_TRAVEL_MINUTES: Final[int] = 8 * 60
ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (45, 180)
# Room for VPN → LOGIN → activity → LOGOUT before the legitimate logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 25

LOCATION_TO_COUNTRY: Final[dict[str, str]] = {
    "LOC-BENGALURU": "India",
    "LOC-HYDERABAD": "India",
    "LOC-LONDON": "United Kingdom",
    "LOC-NEW_YORK": "United States",
    "LOC-SINGAPORE": "Singapore",
    "LOC-REMOTE": "Remote",
    "LOC-TRAVEL": "Travel",
    "LOC-BERLIN": "Germany",
    "LOC-SYDNEY": "Australia",
    "LOC-TOKYO": "Japan",
    "LOC-TORONTO": "Canada",
}

COUNTRY_TO_LOCATION: Final[dict[str, str]] = {
    "India": "LOC-BENGALURU",
    "Singapore": "LOC-SINGAPORE",
    "Germany": "LOC-BERLIN",
    "United Kingdom": "LOC-LONDON",
    "United States": "LOC-NEW_YORK",
    "Australia": "LOC-SYDNEY",
    "Japan": "LOC-TOKYO",
    "Canada": "LOC-TORONTO",
}

COUNTRY_TO_CODE: Final[dict[str, str]] = {
    "India": "IN",
    "Singapore": "SG",
    "Germany": "DE",
    "United Kingdom": "UK",
    "United States": "US",
    "Australia": "AU",
    "Japan": "JP",
    "Canada": "CA",
}

ATTACKER_BROWSERS: Final[tuple[str, ...]] = ("Chrome", "Firefox", "Edge", "Safari")
ATTACKER_OPERATING_SYSTEMS: Final[tuple[str, ...]] = (
    "Windows 11",
    "Ubuntu 24.04",
    "macOS Sonoma",
)

# Believable compromised-account story told through existing event types.
ATTACK_ACTIVITY: Final[tuple[tuple[str, str | None, str], ...]] = (
    (VPN_CONNECT, "RES-VPN", "VPN Access"),
    (LOGIN, None, "Remote Login"),
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "AWS Console Access"),
    (RESOURCE_ACCESS, "RES-PAYROLL", "Payroll Access"),
    (FILE_ACCESS, "RES-FINANCE_DATABASE", "Finance Access"),
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Mass Download"),
    (LOGOUT, None, "Attacker Logout"),
)


@dataclass(slots=True)
class _SessionSlice:
    """Candidate legitimate session selected for compromise."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed attack geometry before events are materialized."""

    origin_country: str
    destination_country: str
    destination_location_id: str
    travel_minutes: int
    attack_start: datetime
    session_start: datetime


@dataclass(slots=True)
class _AttackerPersona:
    """Stable attacker endpoint identity for one injected compromise."""

    device_id: str
    browser: str
    operating_system: str


# ---------------------------------------------------------------------------
# Public entrypoint (signature fixed by AttackInjector)
# ---------------------------------------------------------------------------


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
    """Inject an Impossible Travel compromise for a single attack target.

    Args:
        events: Full enterprise timeline (mutated via append-only copy).
        target: Selected employee/day assignment from the orchestrator.
        attack_id: Stable identifier allocated by the injector.
        config: Attack engine configuration.
        rng: Seeded random generator (deterministic).
        employees: Optional employee index (unused beyond validation hooks).
        profiles: Optional behaviour profiles (unused beyond validation hooks).

    Returns:
        Updated events and an ``AttackRecord``, or ``(events, None)`` when
        the target is skipped / validation rolls the attack back.
    """
    _ = (employees, profiles)

    try:
        employee_events = [event for event in events if event.employee_id == target.employee_id]
        if not _validate_target(employee_events, target, config):
            return events, None

        session = _find_candidate_session(employee_events, target, rng)
        if session is None:
            return events, None

        plan = _build_attack_plan(session, rng)
        if plan is None:
            return events, None

        persona = _build_attacker_persona(session, plan, attack_id, rng)
        id_factory = _make_event_id_factory(events)
        attack_events = _generate_attack_events(
            session=session,
            plan=plan,
            persona=persona,
            attack_id=attack_id,
            target=target,
            id_factory=id_factory,
            rng=rng,
        )
        if not attack_events:
            return events, None

        candidate = _insert_events(events, attack_events)
        if not _validate_attack(
            original_events=events,
            modified_events=candidate,
            attack_events=attack_events,
            target=target,
            plan=plan,
            session=session,
        ):
            return events, None

        record = _create_attack_record(
            attack_id=attack_id,
            target=target,
            plan=plan,
            persona=persona,
            session=session,
            attack_events=attack_events,
        )
        return candidate, record
    except Exception:
        # Never crash the injection pipeline.
        return events, None


# ---------------------------------------------------------------------------
# Stage helpers
# ---------------------------------------------------------------------------


def _validate_target(
    employee_events: Sequence[TimelineEvent],
    target: AttackTarget,
    config: AttackConfig,
) -> bool:
    """Return True when the employee is eligible for Impossible Travel."""
    if len(employee_events) < config.min_events_for_eligibility:
        return False

    has_login = any(event.event_type == LOGIN for event in employee_events)
    if not has_login:
        return False

    existing = _count_existing_attacks(employee_events)
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


def _count_existing_attacks(employee_events: Sequence[TimelineEvent]) -> int:
    """Count prior Impossible Travel markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.IMPOSSIBLE_TRAVEL.value
    )


def _find_candidate_session(
    employee_events: Sequence[TimelineEvent],
    target: AttackTarget,
    rng: random.Random,
) -> _SessionSlice | None:
    """Pick one realistic LOGIN→…→LOGOUT session on the target day."""
    sessions = find_sessions(employee_events, employee_id=target.employee_id)
    candidates: list[_SessionSlice] = []

    for session_id, session_events in sessions.items():
        day_events = [
            event
            for event in session_events
            if event_simulation_date(event) == target.day
        ]
        if not day_events:
            continue

        login_event = next((event for event in day_events if event.event_type == LOGIN), None)
        if login_event is None:
            continue

        logout_event = next(
            (event for event in reversed(day_events) if event.event_type == LOGOUT),
            None,
        )
        # Need room after login for a 10–30 minute impossible hop + activity.
        session_end = logout_event.timestamp if logout_event else day_events[-1].timestamp
        if session_end <= login_event.timestamp + timedelta(
            minutes=MAX_TRAVEL_GAP_MINUTES + ATTACK_BURST_BUFFER_MINUTES
        ):
            continue

        candidates.append(
            _SessionSlice(
                session_id=session_id,
                events=sort_events(day_events),
                login_event=login_event,
                logout_event=logout_event,
            )
        )

    if not candidates:
        return None
    return rng.choice(candidates)


def _country_for_location(location_id: str) -> str:
    """Map a location identifier to a human-readable country name."""
    if location_id in LOCATION_TO_COUNTRY:
        return LOCATION_TO_COUNTRY[location_id]
    token = location_id.upper().replace("LOC-", "").replace("_", " ").title()
    return token or "Unknown"


def _choose_destination_country(origin_country: str, rng: random.Random) -> str:
    """Select a destination country different from the origin."""
    options = [country for country in COUNTRY_TO_LOCATION if country != origin_country]
    if not options:
        options = ["United Kingdom", "United States", "Germany"]
    return rng.choice(options)


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive origin/destination countries and impossible travel timing."""
    origin_country = _country_for_location(session.login_event.location_id)
    destination_country = _choose_destination_country(origin_country, rng)
    destination_location_id = COUNTRY_TO_LOCATION[destination_country]

    travel_minutes = rng.randint(MIN_TRAVEL_GAP_MINUTES, MAX_TRAVEL_GAP_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=travel_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    # Leave buffer before logout for the attacker activity burst.
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None
    if travel_minutes >= MIN_REALISTIC_TRAVEL_MINUTES:
        return None

    return _AttackPlan(
        origin_country=origin_country,
        destination_country=destination_country,
        destination_location_id=destination_location_id,
        travel_minutes=travel_minutes,
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
    )


def _normalize_browser(browser: str | None) -> str:
    """Normalize browser labels for comparison."""
    return (browser or "").strip().lower()


def _normalize_os(operating_system: str | None) -> str:
    """Normalize OS labels for family comparison."""
    token = (operating_system or "").strip().lower()
    if "win" in token:
        return "windows"
    if "mac" in token or "os x" in token or "darwin" in token:
        return "macos"
    if "ubuntu" in token or "linux" in token:
        return "linux"
    return token


def _choose_attacker_browser(victim_browser: str | None, rng: random.Random) -> str:
    """Pick an attacker browser, preferring one different from the victim."""
    victim = _normalize_browser(victim_browser)
    preferred = [browser for browser in ATTACKER_BROWSERS if browser.lower() != victim]
    pool = preferred or list(ATTACKER_BROWSERS)
    return rng.choice(pool)


def _choose_attacker_os(victim_os: str | None, rng: random.Random) -> str:
    """Pick an attacker OS, preferring a different family from the victim."""
    victim_family = _normalize_os(victim_os)
    preferred = [
        operating_system
        for operating_system in ATTACKER_OPERATING_SYSTEMS
        if _normalize_os(operating_system) != victim_family
    ]
    pool = preferred or list(ATTACKER_OPERATING_SYSTEMS)
    return rng.choice(pool)


def _generate_attacker_device_id(
    plan: _AttackPlan,
    attack_id: str,
    victim_device_id: str,
    rng: random.Random,
) -> str:
    """Create a realistic attacker device ID distinct from the victim device."""
    numeric = "".join(ch for ch in attack_id if ch.isdigit()) or "100000"
    serial = int(numeric) % 1_000_000
    country_code = COUNTRY_TO_CODE.get(plan.destination_country, "XX")

    templates = (
        f"DEV-ATTACK-{serial:06d}",
        f"DEV-LAPTOP-{country_code}-{serial % 1000:03d}",
        f"DEV-VPN-{serial % 1000:03d}",
    )
    # Deterministic shuffle so consecutive attacks vary style while staying seeded.
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 1) % 1_000_000:06d}"


def _build_attacker_persona(
    session: _SessionSlice,
    plan: _AttackPlan,
    attack_id: str,
    rng: random.Random,
) -> _AttackerPersona:
    """Build a consistent attacker endpoint persona for the injected burst."""
    victim = session.login_event
    return _AttackerPersona(
        device_id=_generate_attacker_device_id(plan, attack_id, victim.device_id, rng),
        browser=_choose_attacker_browser(victim.browser, rng),
        operating_system=_choose_attacker_os(victim.operating_system, rng),
    )


def _build_risk_indicators(
    plan: _AttackPlan,
    persona: _AttackerPersona,
    stage_label: str,
) -> list[str]:
    """Assemble explainability-friendly risk indicators for one attack event."""
    indicators = [
        "Impossible Travel",
        "New Country",
        "New Device",
        "New Browser",
        "New Operating System",
        f"Origin:{plan.origin_country}",
        f"Destination:{plan.destination_country}",
        stage_label,
    ]
    extras: list[str] = []
    if stage_label == "Payroll Access":
        extras.append("Sensitive HR Data")
    elif stage_label == "Finance Access":
        extras.append("Sensitive Data Access")
    elif stage_label == "Mass Download":
        extras.append("Bulk Exfiltration Pattern")
    elif stage_label == "AWS Console Access":
        extras.append("Cloud Admin Access")

    for item in extras:
        if item not in indicators:
            indicators.append(item)
    return indicators


def _make_event_id_factory(events: Sequence[TimelineEvent]) -> Callable[[], str]:
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


def _generate_attack_events(
    *,
    session: _SessionSlice,
    plan: _AttackPlan,
    persona: _AttackerPersona,
    attack_id: str,
    target: AttackTarget,
    id_factory: Callable[[], str],
    rng: random.Random,
) -> list[TimelineEvent]:
    """Build a believable remote-compromise burst from the destination country."""
    cursor = plan.attack_start
    generated: list[TimelineEvent] = []

    for index, (event_type, resource_id, stage_label) in enumerate(ATTACK_ACTIVITY):
        if index > 0:
            cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))

        metadata = {
            "attack_id": attack_id,
            "attack_type": AttackType.IMPOSSIBLE_TRAVEL.value,
            "is_attack": True,
            "origin_country": plan.origin_country,
            "destination_country": plan.destination_country,
            "travel_minutes": plan.travel_minutes,
            "simulation_date": target.day.isoformat(),
            "work_mode": "attack",
            "attack_stage": index,
            "attack_stage_label": stage_label,
            "attacker_device": persona.device_id,
            "attacker_browser": persona.browser,
            "attacker_os": persona.operating_system,
            "risk_indicators": _build_risk_indicators(plan, persona, stage_label),
        }
        generated.append(
            TimelineEvent(
                event_id=id_factory(),
                employee_id=target.employee_id,
                timestamp=cursor,
                event_type=event_type,
                device_id=persona.device_id,
                location_id=plan.destination_location_id,
                session_id=session.session_id,
                resource_id=resource_id,
                browser=persona.browser,
                operating_system=persona.operating_system,
                result="success",
                metadata=metadata,
            )
        )

    return generated


def _insert_events(
    events: Sequence[TimelineEvent],
    attack_events: Sequence[TimelineEvent],
) -> list[TimelineEvent]:
    """Append attack events and return a chronologically sorted timeline."""
    combined = list(events)
    combined.extend(attack_events)
    return sort_events(combined)


def _validate_attack(
    *,
    original_events: Sequence[TimelineEvent],
    modified_events: Sequence[TimelineEvent],
    attack_events: Sequence[TimelineEvent],
    target: AttackTarget,
    plan: _AttackPlan,
    session: _SessionSlice,
) -> bool:
    """Validate integrity of the injected Impossible Travel burst."""
    if plan.travel_minutes >= MIN_REALISTIC_TRAVEL_MINUTES:
        return False
    if plan.travel_minutes < MIN_TRAVEL_GAP_MINUTES:
        return False
    if plan.destination_country == plan.origin_country:
        return False

    if len(modified_events) != len(original_events) + len(attack_events):
        return False

    # Original events must remain present (append-only).
    original_ids = {event.event_id for event in original_events}
    modified_ids = {event.event_id for event in modified_events}
    if not original_ids.issubset(modified_ids):
        return False

    if any(event.employee_id != target.employee_id for event in attack_events):
        return False

    # Attacker endpoint must differ from the legitimate login device.
    if any(event.device_id == session.login_event.device_id for event in attack_events):
        return False

    timestamps = [event.timestamp for event in modified_events]
    if timestamps != sorted(timestamps):
        return False

    # No duplicate timestamps on the victim's timeline.
    victim_times = [
        event.timestamp
        for event in modified_events
        if event.employee_id == target.employee_id
    ]
    if len(victim_times) != len(set(victim_times)):
        return False

    attack_times = [event.timestamp for event in attack_events]
    if any(timestamp <= plan.session_start for timestamp in attack_times):
        return False
    if any(
        (attack_times[index] - attack_times[index - 1]).total_seconds() <= 0
        for index in range(1, len(attack_times))
    ):
        return False

    if session.logout_event is not None:
        if attack_times[-1] >= session.logout_event.timestamp:
            return False

    measured = int(
        (attack_events[0].timestamp - session.login_event.timestamp).total_seconds() // 60
    )
    if measured != plan.travel_minutes:
        return False

    return True


def _create_attack_record(
    *,
    attack_id: str,
    target: AttackTarget,
    plan: _AttackPlan,
    persona: _AttackerPersona,
    session: _SessionSlice,
    attack_events: Sequence[TimelineEvent],
) -> AttackRecord:
    """Build a fully populated AttackRecord for the Impossible Travel case."""
    attack_end = attack_events[-1].timestamp
    details = {
        "session_id": session.session_id,
        "session_start": plan.session_start.isoformat(sep=" "),
        "attack_start": plan.attack_start.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "original_country": plan.origin_country,
        "new_country": plan.destination_country,
        "travel_minutes": plan.travel_minutes,
        "attacker_device": persona.device_id,
        "attacker_browser": persona.browser,
        "attacker_os": persona.operating_system,
        "modified_event_ids": [event.event_id for event in attack_events],
        "number_of_inserted_events": len(attack_events),
    }
    description = (
        f"Impossible travel: legitimate login from {plan.origin_country} followed "
        f"{plan.travel_minutes} minutes later by remote activity from "
        f"{plan.destination_country} on {persona.device_id} "
        f"({persona.operating_system} / {persona.browser}). "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = target.severity if isinstance(target.severity, Severity) else Severity.HIGH

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.IMPOSSIBLE_TRAVEL,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
