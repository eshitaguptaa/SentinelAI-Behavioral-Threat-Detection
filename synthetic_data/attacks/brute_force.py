"""Brute Force Login attack technique.

Injects a realistic authentication-abuse burst into one existing employee
session: a rapid sequence of failed login attempts (optionally crossing a
lockout warning), a successful compromise, brief resource validation, then
logout.
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
    LOGIN,
    LOGOUT,
    RESOURCE_ACCESS,
    TimelineEvent,
)
from synthetic_data.models import BehaviorProfile, Employee

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FAILED_LOGIN: Final[str] = "FAILED_LOGIN"

MIN_FAILED_ATTEMPTS: Final[int] = 5
MAX_FAILED_ATTEMPTS: Final[int] = 20
FAILED_ATTEMPT_GAP_SECONDS: Final[tuple[int, int]] = (3, 22)
ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (20, 90)

# Offset after the legitimate login before spraying begins.
ATTACK_START_OFFSET_MINUTES: Final[tuple[int, int]] = (5, 40)
# Room for many failed attempts + optional lockout + success + validation.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 50

# Probability of inserting a lockout signal before successful authentication.
LOCKOUT_INCLUSION_PROBABILITY: Final[float] = 0.55

COMPROMISE_METHOD: Final[str] = "Brute Force Login"

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
    "Incorrect Password",
    "Expired Password",
    "Authentication Failed",
    "Account Disabled",
    "Account Locked",
    "Credential Rejected",
)

PASSWORD_STRATEGIES: Final[tuple[str, ...]] = (
    "Password Guessing",
    "Dictionary Attack",
    "Password Spraying",
    "Credential Stuffing",
)

LOCKOUT_STAGES: Final[tuple[str, ...]] = (
    "Lockout Warning",
    "Temporary Lock",
)

AUTHENTICATION_TYPES: Final[tuple[str, ...]] = (
    "Password",
    "Password + VPN",
    "Corporate VPN",
    "SSO Password",
)

VALIDATION_ACTIONS: Final[tuple[tuple[str, str, str], ...]] = (
    (APPLICATION_ACCESS, "RES-EMAIL", "Resource Validation (Email)"),
    (APPLICATION_ACCESS, "RES-MICROSOFT_TEAMS", "Resource Validation (Teams)"),
    (RESOURCE_ACCESS, "RES-HR_PORTAL", "Resource Validation (HR Portal)"),
    (RESOURCE_ACCESS, "RES-CRM", "Resource Validation (CRM)"),
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "Resource Validation (AWS Console)"),
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

MITRE_TACTIC_CREDENTIAL_ACCESS: Final[str] = "Credential Access"
MITRE_TECHNIQUE_BRUTE_FORCE: Final[str] = "Brute Force"
MITRE_TECHNIQUE_PASSWORD_SPRAYING: Final[str] = "Password Spraying"
MITRE_TECHNIQUE_VALID_ACCOUNTS: Final[str] = "Valid Accounts"

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
)


@dataclass(slots=True)
class _SessionSlice:
    """Candidate legitimate session selected for brute-force abuse."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed brute-force geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    successful_login_time: datetime
    validation_time: datetime
    authentication_type: str
    attack_confidence: float
    failed_attempts: int
    failure_reasons: tuple[str, ...]
    lockout_warning: str | None
    location_id: str
    origin_location: str
    password_strategy: str
    validation_action: tuple[str, str, str]


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
    """Inject a Brute Force Login compromise for a single attack target.

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
    """Return True when the employee is eligible for Brute Force Login."""
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
    """Count prior Brute Force Login markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.BRUTE_FORCE_LOGIN.value
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


def _build_failure_reasons(count: int, rng: random.Random) -> tuple[str, ...]:
    """Generate a deterministic per-attempt failure-reason sequence."""
    return tuple(rng.choice(FAILURE_REASONS) for _ in range(count))


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive spraying timing, failure reasons, and optional lockout."""
    offset_minutes = rng.randint(*ATTACK_START_OFFSET_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=offset_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None

    failed_attempts = rng.randint(MIN_FAILED_ATTEMPTS, MAX_FAILED_ATTEMPTS)
    failure_reasons = _build_failure_reasons(failed_attempts, rng)
    lockout_warning = (
        rng.choice(LOCKOUT_STAGES)
        if rng.random() < LOCKOUT_INCLUSION_PROBABILITY
        else None
    )

    avg_fail_gap = (FAILED_ATTEMPT_GAP_SECONDS[0] + FAILED_ATTEMPT_GAP_SECONDS[1]) // 2
    approx_fail_span = failed_attempts * avg_fail_gap
    if lockout_warning is not None:
        approx_fail_span += avg_fail_gap
    successful_login_time = attack_start + timedelta(seconds=approx_fail_span)
    validation_time = successful_login_time + timedelta(
        seconds=(ACTIVITY_GAP_SECONDS[0] + ACTIVITY_GAP_SECONDS[1]) // 2
    )

    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        successful_login_time=successful_login_time,
        validation_time=validation_time,
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
        failed_attempts=failed_attempts,
        failure_reasons=failure_reasons,
        lockout_warning=lockout_warning,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        password_strategy=rng.choice(PASSWORD_STRATEGIES),
        validation_action=rng.choice(VALIDATION_ACTIONS),
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
        f"DEV-BRUTE-{serial % 1000:03d}",
        f"DEV-SPRAY-{serial % 10000:04d}",
        f"DEV-AUTH-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 19) % 1_000_000:06d}"


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


def _mitre_for_stage(stage_label: str, password_strategy: str) -> tuple[str, str]:
    """Map an attack stage to MITRE ATT&CK tactic/technique."""
    if stage_label.startswith("Failed Login") or stage_label in LOCKOUT_STAGES:
        if password_strategy == "Password Spraying":
            return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_PASSWORD_SPRAYING
        return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE
    if stage_label == "Successful Login":
        return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS
    if stage_label.startswith("Resource Validation"):
        return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS
    return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE


def _build_attack_summary(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = [f"{plan.failed_attempts} Failed Logins"]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    if any(label in LOCKOUT_STAGES for label in labels):
        lockout = next(label for label in labels if label in LOCKOUT_STAGES)
        stages.append(lockout)
    if "Successful Login" in labels:
        stages.append("Successful Login")
    if any(label.startswith("Resource Validation") for label in labels):
        stages.append("Resource Validation")
    return " → ".join(stages)


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = [
        "multiple_failed_logins",
        "authentication_failures",
        "new_device",
        "new_browser",
    ]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]

    if plan.password_strategy == "Password Spraying":
        indicators.append("password_spraying")
    if plan.password_strategy == "Credential Stuffing":
        indicators.append("credential_stuffing")
    if "Successful Login" in labels and any(
        event.event_type == FAILED_LOGIN for event in attack_events
    ):
        indicators.append("successful_login_after_failures")
    if any(label in LOCKOUT_STAGES for label in labels):
        indicators.append("lockout_warning")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in indicators:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _build_risk_indicators(*, plan: _AttackPlan, stage_label: str) -> list[str]:
    """Assemble explainability-friendly risk indicators for one attack event."""
    indicators = [
        "Repeated Authentication Failures",
        "Multiple Failed Logins",
        "New Device",
        plan.password_strategy,
        stage_label,
    ]

    if stage_label.startswith("Failed Login"):
        indicators.append("Multiple Failed Logins")
    if stage_label in LOCKOUT_STAGES:
        indicators.append("Account Lockout")
    if stage_label == "Successful Login":
        indicators.append("Successful Login")
    if stage_label.startswith("Resource Validation"):
        indicators.append("Successful Login")

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
    attempt_number: int | None = None,
    failure_reason: str | None = None,
) -> datetime:
    """Materialize one attack event and return its timestamp."""
    mitre_tactic, mitre_technique = _mitre_for_stage(stage_label, plan.password_strategy)
    successful_compromise = stage_label in {
        "Successful Login",
    } or stage_label.startswith("Resource Validation")
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.BRUTE_FORCE_LOGIN.value,
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
        "risk_indicators": _build_risk_indicators(plan=plan, stage_label=stage_label),
        "compromise_method": COMPROMISE_METHOD,
        "authentication_type": plan.authentication_type,
        "authentication_result": result,
        "password_strategy": plan.password_strategy,
        "failed_attempts": plan.failed_attempts,
        "account_lock_warning": plan.lockout_warning,
        "lockout_triggered": stage_label in LOCKOUT_STAGES or plan.lockout_warning is not None,
        "successful_compromise": successful_compromise,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "attack_confidence": plan.attack_confidence,
        "successful_login_time": plan.successful_login_time.isoformat(sep=" "),
        "validation_time": plan.validation_time.isoformat(sep=" "),
        "simulation_date": target.day.isoformat(),
        "work_mode": "attack",
    }
    if attempt_number is not None:
        metadata["attempt_number"] = attempt_number
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
    """Build a brute-force / spray burst ending in brief access validation."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start
    stage_index = 0

    for attempt in range(1, plan.failed_attempts + 1):
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
            attempt_number=attempt,
            failure_reason=plan.failure_reasons[attempt - 1],
        )
        stage_index += 1

    if plan.lockout_warning is not None:
        cursor += timedelta(seconds=rng.randint(*FAILED_ATTEMPT_GAP_SECONDS))
        cursor = _append_event(
            generated=generated,
            cursor=cursor,
            event_type=APPLICATION_ACCESS,
            resource_id="RES-IDENTITY_PROVIDER",
            stage_label=plan.lockout_warning,
            stage_index=stage_index,
            result="failure",
            session=session,
            plan=plan,
            persona=persona,
            attack_id=attack_id,
            target=target,
            id_factory=id_factory,
        )
        stage_index += 1

    cursor += timedelta(seconds=rng.randint(*FAILED_ATTEMPT_GAP_SECONDS))
    plan.successful_login_time = cursor
    cursor = _append_event(
        generated=generated,
        cursor=cursor,
        event_type=LOGIN,
        resource_id=None,
        stage_label="Successful Login",
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

    event_type, resource_id, stage_label = plan.validation_action
    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
    plan.validation_time = cursor
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

    attack_summary = _build_attack_summary(generated, plan)
    ioc = _build_ioc_indicators(generated, plan)
    attack_duration_seconds = int(
        (generated[-1].timestamp - generated[0].timestamp).total_seconds()
    )
    login_iso = plan.successful_login_time.isoformat(sep=" ")
    validation_iso = plan.validation_time.isoformat(sep=" ")
    for event in generated:
        event.metadata["successful_login_time"] = login_iso
        event.metadata["validation_time"] = validation_iso
        event.metadata["failed_attempts"] = plan.failed_attempts
        event.metadata["password_strategy"] = plan.password_strategy
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type
        event.metadata["account_lock_warning"] = plan.lockout_warning

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
    """Validate integrity of the injected Brute Force Login burst."""
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

    if attack_events[-1].event_type != LOGOUT:
        return False

    failed = [event for event in attack_events if event.event_type == FAILED_LOGIN]
    successes = [
        event
        for event in attack_events
        if event.event_type == LOGIN
        and (event.metadata or {}).get("attack_stage_label") == "Successful Login"
    ]
    if len(failed) != plan.failed_attempts:
        return False
    if len(failed) < MIN_FAILED_ATTEMPTS:
        return False
    if len(successes) != 1:
        return False
    if any(event.result != "failure" for event in failed):
        return False
    if successes[0].result != "success":
        return False
    if successes[0].timestamp <= failed[-1].timestamp:
        return False

    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    if "Successful Login" not in labels:
        return False
    if not any(label.startswith("Resource Validation") for label in labels):
        return False

    success_index = labels.index("Successful Login")
    validation_index = next(
        index for index, label in enumerate(labels) if label.startswith("Resource Validation")
    )
    if success_index >= validation_index:
        return False

    if plan.lockout_warning is not None:
        if plan.lockout_warning not in labels:
            return False
        last_fail_index = max(
            index
            for index, event in enumerate(attack_events)
            if event.event_type == FAILED_LOGIN
        )
        lockout_index = labels.index(plan.lockout_warning)
        if not (last_fail_index < lockout_index < success_index):
            return False

    for event in attack_events:
        metadata = event.metadata or {}
        if any(key not in metadata for key in REQUIRED_METADATA_KEYS):
            return False
        if metadata.get("password_strategy") != plan.password_strategy:
            return False
        if metadata.get("failed_attempts") != plan.failed_attempts:
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
    """Build a fully populated AttackRecord for the Brute Force Login case."""
    attack_end = attack_events[-1].timestamp
    attack_summary = (attack_events[0].metadata or {}).get("attack_summary")
    attack_duration_seconds = (attack_events[0].metadata or {}).get(
        "attack_duration_seconds"
    )
    unique_failure_reasons = sorted(set(plan.failure_reasons))
    details = {
        "session_id": session.session_id,
        "session_start": plan.session_start.isoformat(sep=" "),
        "attack_start": plan.attack_start.isoformat(sep=" "),
        "successful_login_time": plan.successful_login_time.isoformat(sep=" "),
        "validation_time": plan.validation_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "failed_attempts": plan.failed_attempts,
        "failure_reasons": unique_failure_reasons,
        "password_strategy": plan.password_strategy,
        "lockout": plan.lockout_warning,
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
    lockout_text = plan.lockout_warning or "none"
    description = (
        f"Brute force login: {plan.failed_attempts} failed attempts via "
        f"{plan.password_strategy} (lockout={lockout_text}), then successful "
        f"{plan.authentication_type} authentication and brief resource validation "
        f"from {persona.device_id} ({persona.user_agent}) via {plan.location_id} "
        f"[{persona.source_ip}] confidence={plan.attack_confidence} "
        f"duration={attack_duration_seconds}s. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = target.severity if isinstance(target.severity, Severity) else Severity.HIGH

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.BRUTE_FORCE_LOGIN,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
