"""Credential Theft attack technique.

Injects a realistic account-compromise burst into one existing employee
session: repeated failed password attempts from a foreign endpoint, followed
by a successful login, VPN access, high-value resource abuse, and logout.
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

FAILED_LOGIN: Final[str] = "FAILED_LOGIN"

MIN_FAILED_ATTEMPTS: Final[int] = 2
MAX_FAILED_ATTEMPTS: Final[int] = 5
FAILED_ATTEMPT_GAP_SECONDS: Final[tuple[int, int]] = (15, 45)
ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (40, 160)

# Offset after the legitimate login before stuffing begins.
ATTACK_START_OFFSET_MINUTES: Final[tuple[int, int]] = (8, 45)
# Room for failed logins + success + post-compromise + logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 30

MIN_POST_COMPROMISE_ACTIONS: Final[int] = 3
MAX_POST_COMPROMISE_ACTIONS: Final[int] = 5

COMPROMISE_METHOD: Final[str] = "Credential Theft"

ATTACKER_LOCATIONS: Final[tuple[str, ...]] = (
    "LOC-REMOTE",
    "LOC-LONDON",
    "LOC-BERLIN",
    "LOC-SINGAPORE",
    "LOC-TORONTO",
    "LOC-NEW_YORK",
)

FAILURE_REASONS: Final[tuple[str, ...]] = (
    "Invalid Password",
    "Wrong Password",
    "Password Expired",
    "Unknown Device",
    "MFA Required",
    "Account Locked",
)

AUTHENTICATION_TYPES: Final[tuple[str, ...]] = (
    "Password",
    "Password + VPN",
    "Corporate VPN",
    "SSO Password",
)

ATTACKER_BROWSERS: Final[tuple[str, ...]] = ("Chrome", "Firefox", "Edge", "Safari")
ATTACKER_OPERATING_SYSTEMS: Final[tuple[str, ...]] = (
    "Windows 11",
    "Ubuntu 24.04",
    "macOS Sonoma",
)

# Believable major versions paired with browser labels for user-agent strings.
BROWSER_VERSIONS: Final[dict[str, tuple[int, ...]]] = {
    "Chrome": (138, 137, 136),
    "Firefox": (142, 141, 140),
    "Edge": (139, 138, 137),
    "Safari": (18, 17),
}

# Public IPv4 first octets (avoid RFC1918 private ranges).
PUBLIC_IP_PREFIXES: Final[tuple[int, ...]] = (34, 185, 104, 52, 13, 20, 44)

MITRE_TACTIC_CREDENTIAL_ACCESS: Final[str] = "Credential Access"
MITRE_TECHNIQUE_BRUTE_FORCE: Final[str] = "Brute Force"
MITRE_TECHNIQUE_VALID_ACCOUNTS: Final[str] = "Valid Accounts"

MIN_ATTACK_CONFIDENCE: Final[float] = 0.90
MAX_ATTACK_CONFIDENCE: Final[float] = 1.00

# Candidate high-value targets for post-compromise browsing.
# VPN is injected separately after successful login (see attack lifecycle).
SENSITIVE_ACTIONS: Final[tuple[tuple[str, str, str], ...]] = (
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "AWS Console Access"),
    (APPLICATION_ACCESS, "RES-AZURE_PORTAL", "Azure Portal Access"),
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "Admin Portal"),
    (APPLICATION_ACCESS, "RES-AZURE_PORTAL", "Cloud Dashboard"),
    (RESOURCE_ACCESS, "RES-PAYROLL", "Payroll Access"),
    (RESOURCE_ACCESS, "RES-FINANCE_DATABASE", "Finance Database"),
    (RESOURCE_ACCESS, "RES-HR_PORTAL", "HR Records"),
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Source Code Repository"),
    (FILE_ACCESS, "RES-CRM", "Customer Database"),
    (FILE_ACCESS, "RES-FINANCE_DATABASE", "Mass Download"),
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
    """Computed credential-theft geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    failed_attempt_count: int
    successful_login_time: datetime
    post_compromise_actions: tuple[tuple[str, str, str], ...]
    location_id: str
    origin_location: str
    authentication_type: str
    attack_confidence: float


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
    """Inject a Credential Theft compromise for a single attack target.

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
    """Return True when the employee is eligible for Credential Theft."""
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
    """Count prior Credential Theft markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.CREDENTIAL_THEFT.value
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
        session_end = logout_event.timestamp if logout_event else day_events[-1].timestamp
        # Need headroom after login for stuffing + post-compromise activity.
        if session_end <= login_event.timestamp + timedelta(
            minutes=ATTACK_START_OFFSET_MINUTES[1] + ATTACK_BURST_BUFFER_MINUTES
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


def _select_post_compromise_actions(
    rng: random.Random,
) -> tuple[tuple[str, str, str], ...]:
    """Choose a deterministic, varied subset of high-value attacker actions."""
    count = rng.randint(MIN_POST_COMPROMISE_ACTIONS, MAX_POST_COMPROMISE_ACTIONS)
    pool = list(SENSITIVE_ACTIONS)
    rng.shuffle(pool)

    selected: list[tuple[str, str, str]] = []
    seen_labels: set[str] = set()
    for action in pool:
        if action[2] in seen_labels:
            continue
        selected.append(action)
        seen_labels.add(action[2])
        if len(selected) >= count:
            break

    priority_tokens = ("AWS", "Azure", "Payroll", "Finance", "Mass Download")
    has_priority = any(
        any(token in label for token in priority_tokens) for *_, label in selected
    )
    if not has_priority:
        priority_pool = [
            action
            for action in SENSITIVE_ACTIONS
            if any(token in action[2] for token in priority_tokens)
        ]
        if priority_pool:
            selected[-1] = rng.choice(priority_pool)
    return tuple(selected)


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive stuffing timing and post-compromise resource selections."""
    offset_minutes = rng.randint(*ATTACK_START_OFFSET_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=offset_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None

    failed_attempt_count = rng.randint(MIN_FAILED_ATTEMPTS, MAX_FAILED_ATTEMPTS)
    # Estimate successful login after the failed attempts with typical gaps.
    approx_fail_span = failed_attempt_count * ((FAILED_ATTEMPT_GAP_SECONDS[0] + FAILED_ATTEMPT_GAP_SECONDS[1]) // 2)
    successful_login_time = attack_start + timedelta(seconds=approx_fail_span)

    post_compromise_actions = _select_post_compromise_actions(rng)
    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        failed_attempt_count=failed_attempt_count,
        successful_login_time=successful_login_time,
        post_compromise_actions=post_compromise_actions,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
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
        f"DEV-STUFFER-{serial % 1000:03d}",
        f"DEV-PHISH-{serial % 10000:04d}",
        f"DEV-VPN-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 7) % 1_000_000:06d}"


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


def _mitre_for_event(event_type: str) -> tuple[str, str]:
    """Map an attack stage event type to MITRE ATT&CK tactic/technique."""
    if event_type == FAILED_LOGIN:
        return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE
    return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS


def _build_attack_summary(attack_events: Sequence[TimelineEvent]) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = []
    if any(event.event_type == FAILED_LOGIN for event in attack_events):
        stages.append("Credential stuffing")
    if any(event.event_type == LOGIN for event in attack_events):
        stages.append("Successful Login")
    if any(event.event_type == VPN_CONNECT for event in attack_events):
        stages.append("VPN")

    for event in attack_events:
        label = (event.metadata or {}).get("attack_stage_label", "")
        if not label:
            continue
        if event.event_type in {FAILED_LOGIN, LOGIN, VPN_CONNECT, LOGOUT}:
            continue
        # Prefer short resource names for the summary chain.
        short = label.replace(" Access", "").replace(" Database", "").strip()
        if short and short not in stages:
            stages.append(short)

    if any(
        "Mass Download" in str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ):
        if "Mass Download" not in stages:
            stages.append("Mass Download")

    return " → ".join(stages) if stages else "Credential Theft"


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent]) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = ["new_device", "new_browser", "remote_login"]
    if any(event.event_type == FAILED_LOGIN for event in attack_events):
        indicators.append("failed_logins")
    if any(event.event_type == VPN_CONNECT for event in attack_events):
        indicators.append("vpn_usage")
    if any(
        "Mass Download" in str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ):
        indicators.append("mass_download")
    return indicators


def _build_risk_indicators(
    *,
    plan: _AttackPlan,
    stage_label: str,
    event_type: str,
) -> list[str]:
    """Assemble explainability-friendly risk indicators for one attack event."""
    indicators = [
        "Credential Theft",
        "New Device",
        "New Browser",
        "New Operating System",
        stage_label,
    ]

    if event_type == FAILED_LOGIN:
        indicators.extend(
            [
                "Multiple Failed Logins",
                f"FailedAttemptCount:{plan.failed_attempt_count}",
            ]
        )
    if event_type == LOGIN:
        indicators.append("Successful Authentication")
    if event_type == VPN_CONNECT or "VPN" in stage_label:
        indicators.append("VPN Access")
    if "AWS" in stage_label or "Azure" in stage_label or "Cloud" in stage_label or "Admin" in stage_label:
        indicators.extend(["Cloud Console", "Privilege Abuse"])
    if "Payroll" in stage_label:
        indicators.append("Payroll Access")
    if "Finance" in stage_label:
        indicators.append("Finance Database")
    if "Mass Download" in stage_label:
        indicators.append("Mass Download")
    if (
        "HR" in stage_label
        or "Source Code" in stage_label
        or "Customer" in stage_label
        or "Admin" in stage_label
        or "Payroll" in stage_label
        or "Finance" in stage_label
    ):
        indicators.append("Sensitive Resource Access")

    # Preserve order while removing duplicates.
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
    failure_reason: str | None = None,
) -> datetime:
    """Materialize one attack event and return its timestamp."""
    mitre_tactic, mitre_technique = _mitre_for_event(event_type)
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.CREDENTIAL_THEFT.value,
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
        "risk_indicators": _build_risk_indicators(
            plan=plan,
            stage_label=stage_label,
            event_type=event_type,
        ),
        "failed_attempt_count": plan.failed_attempt_count,
        "successful_login_time": plan.successful_login_time.isoformat(sep=" "),
        "compromise_method": COMPROMISE_METHOD,
        "authentication_type": plan.authentication_type,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "attack_confidence": plan.attack_confidence,
        "simulation_date": target.day.isoformat(),
        "work_mode": "attack",
    }
    if failure_reason is not None and event_type == FAILED_LOGIN:
        metadata["failure_reason"] = failure_reason

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
    """Build a credential-stuffing then post-compromise activity burst."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start
    stage_index = 0

    # Stage: password guessing / stuffing.
    for attempt in range(1, plan.failed_attempt_count + 1):
        if attempt > 1:
            cursor += timedelta(seconds=rng.randint(*FAILED_ATTEMPT_GAP_SECONDS))
        cursor = _append_event(
            generated=generated,
            cursor=cursor,
            event_type=FAILED_LOGIN,
            resource_id=None,
            stage_label=f"Failed Login Attempt {attempt}",
            stage_index=stage_index,
            result="failure",
            session=session,
            plan=plan,
            persona=persona,
            attack_id=attack_id,
            target=target,
            id_factory=id_factory,
            failure_reason=rng.choice(FAILURE_REASONS),
        )
        stage_index += 1

    # Successful authentication immediately after the final failure.
    cursor += timedelta(seconds=rng.randint(*FAILED_ATTEMPT_GAP_SECONDS))
    plan.successful_login_time = cursor
    cursor = _append_event(
        generated=generated,
        cursor=cursor,
        event_type=LOGIN,
        resource_id=None,
        stage_label="Successful Authentication",
        stage_index=stage_index,
        result="success",
        session=session,
        plan=plan,
        persona=persona,
        attack_id=attack_id,
        target=target,
        id_factory=id_factory,
    )
    stage_index += 1

    # VPN foothold after credential success.
    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
    cursor = _append_event(
        generated=generated,
        cursor=cursor,
        event_type=VPN_CONNECT,
        resource_id="RES-VPN",
        stage_label="VPN Access",
        stage_index=stage_index,
        result="success",
        session=session,
        plan=plan,
        persona=persona,
        attack_id=attack_id,
        target=target,
        id_factory=id_factory,
    )
    stage_index += 1

    # High-value browsing / exfiltration pattern.
    for event_type, resource_id, stage_label in plan.post_compromise_actions:
        cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
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
        stage_index += 1

    # Attacker disconnects last.
    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
    _append_event(
        generated=generated,
        cursor=cursor,
        event_type=LOGOUT,
        resource_id=None,
        stage_label="Attacker Logout",
        stage_index=stage_index,
        result="success",
        session=session,
        plan=plan,
        persona=persona,
        attack_id=attack_id,
        target=target,
        id_factory=id_factory,
    )

    # Keep burst-level fields consistent across every injected event.
    login_iso = plan.successful_login_time.isoformat(sep=" ")
    attack_summary = _build_attack_summary(generated)
    ioc = _build_ioc_indicators(generated)
    attack_duration_seconds = int(
        (generated[-1].timestamp - generated[0].timestamp).total_seconds()
    )
    for event in generated:
        event.metadata["successful_login_time"] = login_iso
        event.metadata["failed_attempt_count"] = plan.failed_attempt_count
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type

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
    """Validate integrity of the injected Credential Theft burst."""
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

    if attack_times[0] <= plan.session_start:
        return False

    if session.logout_event is not None and attack_times[-1] >= session.logout_event.timestamp:
        return False

    failed = [event for event in attack_events if event.event_type == FAILED_LOGIN]
    successes = [event for event in attack_events if event.event_type == LOGIN]
    if len(failed) != plan.failed_attempt_count:
        return False
    if len(successes) != 1:
        return False
    if any(event.result != "failure" for event in failed):
        return False
    if successes[0].result != "success":
        return False
    if successes[0].timestamp <= failed[-1].timestamp:
        return False

    if attack_events[-1].event_type != LOGOUT:
        return False

    # Successful attacker login must follow every failed attempt.
    for failed_event in failed:
        if failed_event.timestamp >= successes[0].timestamp:
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
    """Build a fully populated AttackRecord for the Credential Theft case."""
    accessed_resources = sorted(
        {
            event.resource_id
            for event in attack_events
            if event.resource_id
        }
    )
    attack_end = attack_events[-1].timestamp
    attack_summary = (attack_events[0].metadata or {}).get("attack_summary")
    details = {
        "session_id": session.session_id,
        "session_start": plan.session_start.isoformat(sep=" "),
        "attack_start": plan.attack_start.isoformat(sep=" "),
        "successful_login_time": plan.successful_login_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "failed_attempt_count": plan.failed_attempt_count,
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
        "attack_duration_seconds": (attack_events[0].metadata or {}).get(
            "attack_duration_seconds"
        ),
        "accessed_resources": accessed_resources,
        "modified_event_ids": [event.event_id for event in attack_events],
        "number_of_inserted_events": len(attack_events),
    }
    description = (
        f"Credential theft: {plan.failed_attempt_count} failed password attempts "
        f"followed by successful {plan.authentication_type} authentication, "
        f"VPN access, and sensitive resource use "
        f"({', '.join(accessed_resources) if accessed_resources else 'none'}) "
        f"from {persona.device_id} ({persona.operating_system} / {persona.browser}) "
        f"via {plan.location_id} [{persona.source_ip}]. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = target.severity if isinstance(target.severity, Severity) else Severity.HIGH

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.CREDENTIAL_THEFT,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
