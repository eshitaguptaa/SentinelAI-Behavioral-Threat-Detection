"""After-Hours Access attack technique.

Injects a subtle off-hours compromise burst linked to one legitimate employee
session: a late-night or early-morning login, light sensitive-resource access,
a small download, then logout — abnormal timing without bulk exfiltration.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
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
)
from synthetic_data.models import BehaviorProfile, Employee

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (45, 180)

# Short burst: login → a few resources → small download → logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 25

MIN_SENSITIVE_ACTIONS: Final[int] = 2
MAX_SENSITIVE_ACTIONS: Final[int] = 4

COMPROMISE_METHOD: Final[str] = "After Hours Access"

ATTACKER_LOCATIONS: Final[tuple[str, ...]] = (
    "LOC-REMOTE",
    "LOC-LONDON",
    "LOC-BERLIN",
    "LOC-SINGAPORE",
    "LOC-TORONTO",
    "LOC-NEW_YORK",
)

AUTHENTICATION_TYPES: Final[tuple[str, ...]] = (
    "Password",
    "Password + VPN",
    "Corporate VPN",
    "SSO Password",
)

DEVICE_TYPES: Final[tuple[str, ...]] = (
    "Laptop",
    "Workstation",
    "Remote Jump Host",
    "Personal Device",
)

NIGHT_PERIODS: Final[tuple[str, ...]] = (
    "late_night",
    "early_morning",
)

# Late night: 22:00–23:59 (start capped so the burst finishes before midnight).
LATE_NIGHT_START_HOUR: Final[int] = 22
LATE_NIGHT_START_MAX_MINUTE: Final[int] = 35

# Early morning: 00:00–05:30.
EARLY_MORNING_START_MINUTE: Final[int] = 15
EARLY_MORNING_END_HOUR: Final[int] = 5
EARLY_MORNING_END_MINUTE: Final[int] = 0

DOWNLOAD_SIZES_MB: Final[tuple[int, ...]] = (5, 12, 18, 25, 35)

SENSITIVE_ACTIONS: Final[tuple[tuple[str, str, str], ...]] = (
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Sensitive File Access"),
    (RESOURCE_ACCESS, "RES-FINANCE_DATABASE", "Financial System"),
    (RESOURCE_ACCESS, "RES-PAYROLL", "Payroll Access"),
    (RESOURCE_ACCESS, "RES-HR_PORTAL", "HR Portal"),
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "Configuration Access"),
    (APPLICATION_ACCESS, "RES-AZURE_PORTAL", "Cloud Configuration"),
    (RESOURCE_ACCESS, "RES-SECURITY_POLICIES", "Configuration Access"),
    (FILE_ACCESS, "RES-CRM", "Customer Records"),
    (APPLICATION_ACCESS, "RES-EMAIL", "Mailbox Access"),
)

SMALL_DOWNLOAD_ACTION: Final[tuple[str, str | None, str]] = (
    FILE_ACCESS,
    "RES-CLOUD_STORAGE",
    "Small Download",
)

ATTACKER_BROWSERS: Final[tuple[str, ...]] = ("Chrome", "Firefox", "Edge", "Safari")
ATTACKER_OPERATING_SYSTEMS: Final[tuple[str, ...]] = (
    "Windows 11",
    "Ubuntu 24.04",
    "macOS Sonoma",
)

BROWSER_VERSIONS: Final[dict[str, tuple[int, ...]]] = {
    "Chrome": (138, 137, 136),
    "Firefox": (142, 141, 140),
    "Edge": (139, 138, 137),
    "Safari": (18, 17),
}

PUBLIC_IP_PREFIXES: Final[tuple[int, ...]] = (34, 185, 104, 52, 13, 20, 44)

MIN_ATTACK_CONFIDENCE: Final[float] = 0.90
MAX_ATTACK_CONFIDENCE: Final[float] = 1.00

MITRE_TACTIC_INITIAL_ACCESS: Final[str] = "Initial Access"
MITRE_TACTIC_DISCOVERY: Final[str] = "Discovery"
MITRE_TACTIC_COLLECTION: Final[str] = "Collection"
MITRE_TACTIC_LATERAL_MOVEMENT: Final[str] = "Lateral Movement"

MITRE_TECHNIQUE_VALID_ACCOUNTS: Final[str] = "Valid Accounts"
MITRE_TECHNIQUE_REMOTE_SERVICES: Final[str] = "Remote Services"
MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM: Final[str] = "Data from Local System"
MITRE_TECHNIQUE_SYSTEM_INFO_DISCOVERY: Final[str] = "System Information Discovery"

REQUIRED_METADATA_KEYS: Final[tuple[str, ...]] = (
    "attack_id",
    "attack_type",
    "attack_stage",
    "attack_stage_label",
    "attacker_device",
    "attacker_browser",
    "attacker_os",
    "attacker_user_agent",
    "source_ip",
    "origin_location",
    "destination_location",
    "authentication_type",
    "attack_confidence",
    "risk_indicators",
    "mitre_tactic",
    "mitre_technique",
    "simulation_date",
    "ioc",
    "attack_summary",
    "attack_duration_seconds",
    "after_hours",
    "night_window",
    "login_hour",
    "download_size_mb",
)


@dataclass(slots=True)
class _SessionSlice:
    """Candidate legitimate daytime session used for persona contrast."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed after-hours geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    login_time: datetime
    logout_time: datetime
    authentication_type: str
    attack_confidence: float
    location_id: str
    origin_location: str
    night_period: str
    resource_sequence: tuple[tuple[str, str | None, str], ...]
    download_size_mb: int
    device_type: str


@dataclass(slots=True)
class _AttackerPersona:
    """Stable attacker endpoint identity for one injected compromise."""

    device_id: str
    browser: str
    operating_system: str
    user_agent: str
    source_ip: str


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
    """Inject an After-Hours Access compromise for a single attack target.

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

        plan = _build_attack_plan(session, target.day, employee_events, rng)
        if plan is None:
            return events, None

        persona = _build_attacker_persona(session, attack_id, rng)
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
    """Return True when the employee is eligible for After-Hours Access."""
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
    """Count prior After-Hours Access markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.AFTER_HOURS_ACCESS.value
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


def _is_after_hours(moment: datetime) -> bool:
    """Return True when ``moment`` falls in an allowed night window."""
    clock = moment.time()
    if time(22, 0) <= clock <= time(23, 59, 59):
        return True
    if time(0, 0) <= clock <= time(5, 30):
        return True
    return False


def _is_business_hours(moment: datetime) -> bool:
    """Return True for forbidden daytime hours (08:00–18:00)."""
    clock = moment.time()
    return time(8, 0) <= clock < time(18, 0)


def _occupied_timestamps(
    employee_events: Sequence[TimelineEvent],
    day: date,
) -> set[datetime]:
    """Collect timestamps already used by the employee on ``day``."""
    return {
        event.timestamp
        for event in employee_events
        if event_simulation_date(event) == day
    }


def _choose_night_start(
    *,
    day: date,
    session: _SessionSlice,
    occupied: set[datetime],
    rng: random.Random,
) -> tuple[datetime, str] | None:
    """Pick a free after-hours start time on the simulation day."""
    periods = list(NIGHT_PERIODS)
    rng.shuffle(periods)

    for period in periods:
        if period == "late_night":
            minute = rng.randint(0, LATE_NIGHT_START_MAX_MINUTE)
            candidate = datetime.combine(
                day,
                time(LATE_NIGHT_START_HOUR, minute, rng.randint(0, 50)),
            )
            if session.logout_event is not None and candidate <= session.logout_event.timestamp:
                pushed = session.logout_event.timestamp + timedelta(
                    minutes=rng.randint(30, 120)
                )
                if _is_after_hours(pushed) and not _is_business_hours(pushed):
                    candidate = pushed.replace(microsecond=0)
                else:
                    candidate = datetime.combine(
                        day,
                        time(22, rng.randint(5, 35), rng.randint(0, 50)),
                    )
                    if candidate <= session.logout_event.timestamp:
                        continue
        else:
            hour = rng.randint(0, EARLY_MORNING_END_HOUR)
            if hour == 0:
                minute = rng.randint(EARLY_MORNING_START_MINUTE, 59)
            elif hour == EARLY_MORNING_END_HOUR:
                minute = rng.randint(0, EARLY_MORNING_END_MINUTE)
            else:
                minute = rng.randint(0, 59)
            candidate = datetime.combine(day, time(hour, minute, rng.randint(0, 50)))
            # Early morning must finish before the legitimate daytime login.
            if (
                candidate + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES)
                >= session.login_event.timestamp
            ):
                continue

        if not _is_after_hours(candidate) or _is_business_hours(candidate):
            continue

        burst_end = candidate + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES)
        if period == "late_night" and burst_end.date() != day:
            continue
        if period == "early_morning" and (
            not _is_after_hours(burst_end) or _is_business_hours(burst_end)
        ):
            continue

        if any(candidate <= stamp <= burst_end for stamp in occupied):
            adjusted = candidate
            resolved = False
            for _ in range(8):
                adjusted += timedelta(seconds=rng.randint(15, 45))
                adjusted_end = adjusted + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES)
                if not _is_after_hours(adjusted) or _is_business_hours(adjusted):
                    break
                if not any(adjusted <= stamp <= adjusted_end for stamp in occupied):
                    candidate = adjusted
                    resolved = True
                    break
            if not resolved:
                continue

        return candidate, period

    return None


def _select_resource_sequence(
    rng: random.Random,
) -> tuple[tuple[str, str | None, str], ...]:
    """Build a subtle after-hours activity spine with light variation."""
    count = rng.randint(MIN_SENSITIVE_ACTIONS, MAX_SENSITIVE_ACTIONS)
    pool = list(SENSITIVE_ACTIONS)
    rng.shuffle(pool)

    selected: list[tuple[str, str | None, str]] = []
    seen_labels: set[str] = set()
    for action in pool:
        if action[2] in seen_labels:
            continue
        selected.append(action)
        seen_labels.add(action[2])
        if len(selected) >= count:
            break

    sequence: list[tuple[str, str | None, str]] = [
        (LOGIN, None, "Late Night Login"),
    ]
    sequence.extend(selected)
    sequence.append(SMALL_DOWNLOAD_ACTION)
    return tuple(sequence)


def _build_attack_plan(
    session: _SessionSlice,
    day: date,
    employee_events: Sequence[TimelineEvent],
    rng: random.Random,
) -> _AttackPlan | None:
    """Derive night-window timing and a light resource sequence."""
    occupied = _occupied_timestamps(employee_events, day)
    night_choice = _choose_night_start(
        day=day,
        session=session,
        occupied=occupied,
        rng=rng,
    )
    if night_choice is None:
        return None

    attack_start, night_period = night_choice
    resource_sequence = _select_resource_sequence(rng)
    approx_gap = (ACTIVITY_GAP_SECONDS[0] + ACTIVITY_GAP_SECONDS[1]) // 2
    logout_time = attack_start + timedelta(
        seconds=approx_gap * max(len(resource_sequence), 1)
    )

    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        login_time=attack_start,
        logout_time=logout_time,
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        night_period=night_period,
        resource_sequence=resource_sequence,
        download_size_mb=rng.choice(DOWNLOAD_SIZES_MB),
        device_type=rng.choice(DEVICE_TYPES),
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
    attack_id: str,
    victim_device_id: str,
    rng: random.Random,
) -> str:
    """Create a realistic attacker device ID distinct from the victim device."""
    numeric = "".join(ch for ch in attack_id if ch.isdigit()) or "100000"
    serial = int(numeric) % 1_000_000

    templates = (
        f"DEV-ATTACK-{serial:06d}",
        f"DEV-NIGHT-{serial % 1000:03d}",
        f"DEV-OFFHOUR-{serial % 10000:04d}",
        f"DEV-REMOTE-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 23) % 1_000_000:06d}"


def _generate_attacker_user_agent(
    browser: str,
    operating_system: str,
    rng: random.Random,
) -> str:
    """Build a compact browser/OS user-agent label for SOC timelines."""
    versions = BROWSER_VERSIONS.get(browser, (100,))
    version = rng.choice(versions)
    return f"{browser} {version} / {operating_system}"


def _generate_attacker_source_ip(rng: random.Random) -> str:
    """Generate a deterministic fake public IPv4 address."""
    prefix = rng.choice(PUBLIC_IP_PREFIXES)
    return f"{prefix}.{rng.randint(1, 254)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _build_attacker_persona(
    session: _SessionSlice,
    attack_id: str,
    rng: random.Random,
) -> _AttackerPersona:
    """Build a consistent attacker endpoint persona for the injected burst."""
    victim = session.login_event
    browser = _choose_attacker_browser(victim.browser, rng)
    operating_system = _choose_attacker_os(victim.operating_system, rng)
    return _AttackerPersona(
        device_id=_generate_attacker_device_id(attack_id, victim.device_id, rng),
        browser=browser,
        operating_system=operating_system,
        user_agent=_generate_attacker_user_agent(browser, operating_system, rng),
        source_ip=_generate_attacker_source_ip(rng),
    )


def _mitre_for_stage(stage_label: str) -> tuple[str, str]:
    """Map an attack stage to MITRE ATT&CK tactic/technique."""
    if stage_label == "Late Night Login":
        return MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS
    if stage_label in {"Configuration Access", "Cloud Configuration"}:
        return MITRE_TACTIC_DISCOVERY, MITRE_TECHNIQUE_SYSTEM_INFO_DISCOVERY
    if stage_label == "Small Download":
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM
    if stage_label in {
        "Sensitive File Access",
        "Financial System",
        "Payroll Access",
        "HR Portal",
        "Customer Records",
        "Mailbox Access",
    }:
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM
    if stage_label == "Attacker Logout":
        return MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS
    return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_REMOTE_SERVICES


def _build_attack_summary(attack_events: Sequence[TimelineEvent]) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = []
    for event in attack_events:
        label = str((event.metadata or {}).get("attack_stage_label", ""))
        if not label:
            continue
        if label == "Late Night Login":
            short = "Late Night Login"
        elif label == "HR Portal":
            short = "HR Portal"
        elif label in {"Configuration Access", "Cloud Configuration"}:
            short = "Configuration"
        elif label == "Small Download":
            short = "Small Download"
        elif label == "Attacker Logout":
            short = "Logout"
        elif label == "Financial System":
            short = "Financial System"
        elif label == "Sensitive File Access":
            short = "Sensitive Files"
        else:
            short = label.replace(" Access", "").strip()
        if short and short not in stages:
            stages.append(short)
    return " → ".join(stages) if stages else "After Hours Access"


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent]) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = [
        "after_hours_login",
        "late_night_activity",
        "off_hours_access",
        "new_device",
        "new_browser",
    ]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    if "Small Download" in labels:
        indicators.append("small_download")
    if any(
        label
        in {
            "Sensitive File Access",
            "Financial System",
            "Payroll Access",
            "HR Portal",
            "Configuration Access",
            "Cloud Configuration",
            "Customer Records",
        }
        for label in labels
    ):
        indicators.append("sensitive_resources")
    return indicators


def _build_risk_indicators(*, stage_label: str) -> list[str]:
    """Assemble explainability-friendly risk indicators for one attack event."""
    indicators = [
        "After Hours",
        "Late Night",
        "Off Hours Login",
        "New Device",
        stage_label,
    ]
    if stage_label in {
        "Sensitive File Access",
        "Financial System",
        "Payroll Access",
        "HR Portal",
        "Customer Records",
    }:
        indicators.append("Sensitive Resources")
    if stage_label in {"Configuration Access", "Cloud Configuration"}:
        indicators.append("Configuration Access")
    if stage_label == "Small Download":
        indicators.append("Small Download")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in indicators:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


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


def _append_event(
    *,
    generated: list[TimelineEvent],
    cursor: datetime,
    event_type: str,
    resource_id: str | None,
    stage_label: str,
    stage_index: int,
    result: str,
    session: _SessionSlice,
    plan: _AttackPlan,
    persona: _AttackerPersona,
    attack_id: str,
    target: AttackTarget,
    id_factory: Callable[[], str],
) -> datetime:
    """Materialize one attack event and return its timestamp."""
    mitre_tactic, mitre_technique = _mitre_for_stage(stage_label)
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.AFTER_HOURS_ACCESS.value,
        "is_attack": True,
        "attack_stage": stage_index,
        "attack_stage_label": stage_label,
        "attacker_device": persona.device_id,
        "attacker_browser": persona.browser,
        "attacker_os": persona.operating_system,
        "attacker_user_agent": persona.user_agent,
        "source_ip": persona.source_ip,
        "attacker_location": plan.location_id,
        "origin_location": plan.origin_location,
        "destination_location": plan.location_id,
        "risk_indicators": _build_risk_indicators(stage_label=stage_label),
        "compromise_method": COMPROMISE_METHOD,
        "authentication_type": plan.authentication_type,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "attack_confidence": plan.attack_confidence,
        "after_hours": True,
        "night_window": plan.night_period,
        "login_hour": plan.login_time.hour,
        "download_size_mb": plan.download_size_mb,
        "device_type": plan.device_type,
        "simulation_date": target.day.isoformat(),
        "work_mode": "attack",
    }

    generated.append(
        TimelineEvent(
            event_id=id_factory(),
            employee_id=target.employee_id,
            timestamp=cursor,
            event_type=event_type,
            device_id=persona.device_id,
            location_id=plan.location_id,
            session_id=session.session_id,
            resource_id=resource_id,
            browser=persona.browser,
            operating_system=persona.operating_system,
            result=result,
            metadata=metadata,
        )
    )
    return cursor


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
    """Build a subtle after-hours login and light-access burst."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start

    for stage_index, (event_type, resource_id, stage_label) in enumerate(
        plan.resource_sequence
    ):
        if stage_index > 0:
            cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
            if _is_business_hours(cursor) or not _is_after_hours(cursor):
                return []

        if stage_label == "Late Night Login":
            plan.login_time = cursor

        cursor = _append_event(
            generated=generated,
            cursor=cursor,
            event_type=event_type,
            resource_id=resource_id,
            stage_label=stage_label,
            stage_index=stage_index,
            result="success",
            session=session,
            plan=plan,
            persona=persona,
            attack_id=attack_id,
            target=target,
            id_factory=id_factory,
        )

    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
    if _is_business_hours(cursor) or not _is_after_hours(cursor):
        return []

    plan.logout_time = cursor
    _append_event(
        generated=generated,
        cursor=cursor,
        event_type=LOGOUT,
        resource_id=None,
        stage_label="Attacker Logout",
        stage_index=len(plan.resource_sequence),
        result="success",
        session=session,
        plan=plan,
        persona=persona,
        attack_id=attack_id,
        target=target,
        id_factory=id_factory,
    )

    attack_summary = _build_attack_summary(generated)
    ioc = _build_ioc_indicators(generated)
    attack_duration_seconds = int(
        (generated[-1].timestamp - generated[0].timestamp).total_seconds()
    )
    for event in generated:
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type
        event.metadata["after_hours"] = True
        event.metadata["night_window"] = plan.night_period
        event.metadata["login_hour"] = plan.login_time.hour
        event.metadata["download_size_mb"] = plan.download_size_mb
        event.metadata["device_type"] = plan.device_type

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
    """Validate integrity of the injected After-Hours Access burst."""
    if len(modified_events) != len(original_events) + len(attack_events):
        return False

    original_ids = {event.event_id for event in original_events}
    modified_ids = {event.event_id for event in modified_events}
    if not original_ids.issubset(modified_ids):
        return False

    if any(event.employee_id != target.employee_id for event in attack_events):
        return False

    if any(event.device_id == session.login_event.device_id for event in attack_events):
        return False

    timestamps = [event.timestamp for event in modified_events]
    if timestamps != sorted(timestamps):
        return False

    victim_times = [
        event.timestamp
        for event in modified_events
        if event.employee_id == target.employee_id
    ]
    if len(victim_times) != len(set(victim_times)):
        return False

    attack_times = [event.timestamp for event in attack_events]
    if any(
        (attack_times[index] - attack_times[index - 1]).total_seconds() <= 0
        for index in range(1, len(attack_times))
    ):
        return False

    if attack_events[-1].event_type != LOGOUT:
        return False

    # Every injected timestamp must be outside business hours.
    if any(_is_business_hours(stamp) for stamp in attack_times):
        return False
    if any(not _is_after_hours(stamp) for stamp in attack_times):
        return False

    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    if "Late Night Login" not in labels:
        return False
    if "Small Download" not in labels:
        return False
    if labels[0] != "Late Night Login":
        return False
    if labels.index("Small Download") <= labels.index("Late Night Login"):
        return False

    login_events = [event for event in attack_events if event.event_type == LOGIN]
    if len(login_events) != 1:
        return False
    if login_events[0].timestamp.hour not in set(range(0, 6)) | {22, 23}:
        return False

    if plan.download_size_mb > 35:
        return False

    for event in attack_events:
        metadata = event.metadata or {}
        if any(key not in metadata for key in REQUIRED_METADATA_KEYS):
            return False
        if metadata.get("after_hours") is not True:
            return False
        if metadata.get("night_window") != plan.night_period:
            return False
        if metadata.get("download_size_mb") != plan.download_size_mb:
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
    """Build a fully populated AttackRecord for the After-Hours Access case."""
    accessed_resources = sorted(
        {
            event.resource_id
            for event in attack_events
            if event.resource_id
        }
    )
    attack_end = attack_events[-1].timestamp
    attack_summary = (attack_events[0].metadata or {}).get("attack_summary")
    attack_duration_seconds = (attack_events[0].metadata or {}).get(
        "attack_duration_seconds"
    )
    details = {
        "session_id": session.session_id,
        "session_start": plan.session_start.isoformat(sep=" "),
        "attack_start": plan.attack_start.isoformat(sep=" "),
        "login_time": plan.login_time.isoformat(sep=" "),
        "logout_time": plan.logout_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "login_hour": plan.login_time.hour,
        "night_window": plan.night_period,
        "download_size_mb": plan.download_size_mb,
        "device_type": plan.device_type,
        "resources_accessed": accessed_resources,
        "compromise_method": COMPROMISE_METHOD,
        "authentication_type": plan.authentication_type,
        "attacker_device": persona.device_id,
        "attacker_browser": persona.browser,
        "attacker_os": persona.operating_system,
        "attacker_user_agent": persona.user_agent,
        "source_ip": persona.source_ip,
        "attacker_location": plan.location_id,
        "origin_location": plan.origin_location,
        "destination_location": plan.location_id,
        "attack_summary": attack_summary,
        "attack_confidence": plan.attack_confidence,
        "attack_duration_seconds": attack_duration_seconds,
        "modified_event_ids": [event.event_id for event in attack_events],
        "number_of_inserted_events": len(attack_events),
    }
    description = (
        f"After-hours access: {plan.night_period} login at hour "
        f"{plan.login_time.hour:02d} with light sensitive access and "
        f"{plan.download_size_mb} MB download using {plan.authentication_type} "
        f"from {persona.device_id} ({persona.user_agent}) via {plan.location_id} "
        f"[{persona.source_ip}] confidence={plan.attack_confidence} "
        f"duration={attack_duration_seconds}s. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = target.severity if isinstance(target.severity, Severity) else Severity.MEDIUM

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.AFTER_HOURS_ACCESS,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
