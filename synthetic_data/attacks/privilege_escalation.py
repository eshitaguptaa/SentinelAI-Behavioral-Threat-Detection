"""Privilege Escalation attack technique.

Injects a realistic privilege-abuse burst into one existing employee session:
optional VPN access, admin-portal activity, role/group elevation, then access
to previously restricted resources and a mass download before logout.
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

ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (40, 160)

# Offset after the legitimate login before privilege abuse begins.
ATTACK_START_OFFSET_MINUTES: Final[tuple[int, int]] = (12, 55)
# Room for optional VPN + escalation + resource abuse + logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 35

MIN_SENSITIVE_RESOURCES: Final[int] = 2
MAX_SENSITIVE_RESOURCES: Final[int] = 4

# Probability of inserting a VPN foothold before admin-portal abuse.
VPN_INCLUSION_PROBABILITY: Final[float] = 0.70

COMPROMISE_METHOD: Final[str] = "Privilege Escalation"

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
    "Privileged SSO",
)

ROLE_BEFORE_OPTIONS: Final[tuple[str, ...]] = (
    "Employee",
    "Standard User",
    "Contractor",
    "Power User",
)

ROLE_AFTER_OPTIONS: Final[tuple[str, ...]] = (
    "Administrator",
    "Domain Administrator",
    "Cloud Administrator",
    "Security Administrator",
)

ADMIN_GROUPS: Final[tuple[str, ...]] = (
    "Domain Admins",
    "Enterprise Admins",
    "Global Administrators",
    "Schema Admins",
    "Privileged Role Administrators",
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

MITRE_TACTIC_PRIVILEGE_ESCALATION: Final[str] = "Privilege Escalation"
MITRE_TACTIC_PERSISTENCE: Final[str] = "Persistence"
MITRE_TACTIC_DEFENSE_EVASION: Final[str] = "Defense Evasion"
MITRE_TECHNIQUE_VALID_ACCOUNTS: Final[str] = "Valid Accounts"
MITRE_TECHNIQUE_ACCOUNT_MANIPULATION: Final[str] = "Account Manipulation"

# Fixed escalation spine (VPN may be prepended during generation).
ADMIN_PORTAL_ACTION: Final[tuple[str, str, str]] = (
    APPLICATION_ACCESS,
    "RES-AWS_CONSOLE",
    "Admin Portal",
)
ESCALATION_ACTION: Final[tuple[str, str, str]] = (
    APPLICATION_ACCESS,
    "RES-IAM_DASHBOARD",
    "Privilege Escalation",
)
ROLE_CHANGE_ACTION: Final[tuple[str, str, str]] = (
    RESOURCE_ACCESS,
    "RES-ACTIVE_DIRECTORY",
    "Role / Group Modification",
)
CONFIG_ACTION: Final[tuple[str, str, str]] = (
    RESOURCE_ACCESS,
    "RES-SECURITY_POLICIES",
    "Sensitive Configuration Access",
)
MASS_DOWNLOAD_ACTION: Final[tuple[str, str, str]] = (
    FILE_ACCESS,
    "RES-SOURCE_CODE_REPOSITORY",
    "Mass Download",
)

# Previously restricted / high-value systems accessed after elevation.
SENSITIVE_RESOURCES: Final[tuple[tuple[str, str, str], ...]] = (
    (APPLICATION_ACCESS, "RES-AWS_CONSOLE", "AWS Console"),
    (APPLICATION_ACCESS, "RES-AZURE_PORTAL", "Azure Portal"),
    (RESOURCE_ACCESS, "RES-ACTIVE_DIRECTORY", "Active Directory"),
    (RESOURCE_ACCESS, "RES-DOMAIN_CONTROLLER", "Domain Controller"),
    (APPLICATION_ACCESS, "RES-IAM_DASHBOARD", "IAM Dashboard"),
    (RESOURCE_ACCESS, "RES-SECURITY_POLICIES", "Security Policies"),
    (RESOURCE_ACCESS, "RES-FINANCE_DATABASE", "Finance Database"),
    (RESOURCE_ACCESS, "RES-PAYROLL", "Payroll"),
    (FILE_ACCESS, "RES-CRM", "Customer Database"),
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Source Code Repository"),
    (APPLICATION_ACCESS, "RES-KUBERNETES_CLUSTER", "Kubernetes Cluster"),
    (RESOURCE_ACCESS, "RES-PRODUCTION_SERVERS", "Production Servers"),
)

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
    """Candidate legitimate session selected for privilege abuse."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed privilege-escalation geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    escalation_time: datetime
    role_before: str
    role_assigned: str
    admin_group: str
    authentication_type: str
    attack_confidence: float
    location_id: str
    origin_location: str
    include_vpn: bool
    resource_sequence: tuple[tuple[str, str, str], ...]


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
    """Inject a Privilege Escalation compromise for a single attack target.

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
    """Return True when the employee is eligible for Privilege Escalation."""
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
    """Count prior Privilege Escalation markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.PRIVILEGE_ESCALATION.value
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
        # Need headroom after login for escalation + post-elevation activity.
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


def _select_sensitive_resources(
    rng: random.Random,
) -> tuple[tuple[str, str, str], ...]:
    """Choose a deterministic subset of previously restricted resources."""
    count = rng.randint(MIN_SENSITIVE_RESOURCES, MAX_SENSITIVE_RESOURCES)
    pool = list(SENSITIVE_RESOURCES)
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
    return tuple(selected)


def _build_resource_sequence(
    rng: random.Random,
    *,
    include_vpn: bool,
) -> tuple[tuple[str, str, str], ...]:
    """Assemble the ordered privilege-abuse activity spine."""
    sequence: list[tuple[str, str, str]] = []
    if include_vpn:
        sequence.append((VPN_CONNECT, "RES-VPN", "VPN Access"))

    sequence.append(ADMIN_PORTAL_ACTION)
    sequence.append(ESCALATION_ACTION)
    sequence.append(ROLE_CHANGE_ACTION)
    sequence.extend(_select_sensitive_resources(rng))
    sequence.append(CONFIG_ACTION)
    sequence.append(MASS_DOWNLOAD_ACTION)
    return tuple(sequence)


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive escalation timing, role change, and resource selections."""
    offset_minutes = rng.randint(*ATTACK_START_OFFSET_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=offset_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None

    include_vpn = rng.random() < VPN_INCLUSION_PROBABILITY
    resource_sequence = _build_resource_sequence(rng, include_vpn=include_vpn)

    # Estimate escalation stage timing (after optional VPN + admin portal).
    stages_before_escalation = 2 if include_vpn else 1
    approx_gap = (ACTIVITY_GAP_SECONDS[0] + ACTIVITY_GAP_SECONDS[1]) // 2
    escalation_time = attack_start + timedelta(
        seconds=stages_before_escalation * approx_gap
    )

    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        escalation_time=escalation_time,
        role_before=rng.choice(ROLE_BEFORE_OPTIONS),
        role_assigned=rng.choice(ROLE_AFTER_OPTIONS),
        admin_group=rng.choice(ADMIN_GROUPS),
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        include_vpn=include_vpn,
        resource_sequence=resource_sequence,
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
        f"DEV-PRIV-{serial % 1000:03d}",
        f"DEV-ADMIN-{serial % 10000:04d}",
        f"DEV-JUMP-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 11) % 1_000_000:06d}"


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


def _mitre_for_stage(stage_label: str, event_type: str) -> tuple[str, str]:
    """Map an attack stage to MITRE ATT&CK tactic/technique."""
    if stage_label in {"Privilege Escalation", "Admin Portal"}:
        return MITRE_TACTIC_PRIVILEGE_ESCALATION, MITRE_TECHNIQUE_ACCOUNT_MANIPULATION
    if stage_label == "Role / Group Modification":
        return MITRE_TACTIC_PERSISTENCE, MITRE_TECHNIQUE_ACCOUNT_MANIPULATION
    if stage_label in {"Sensitive Configuration Access", "Security Policies", "VPN Access"}:
        return MITRE_TACTIC_DEFENSE_EVASION, MITRE_TECHNIQUE_VALID_ACCOUNTS
    if event_type == VPN_CONNECT:
        return MITRE_TACTIC_DEFENSE_EVASION, MITRE_TECHNIQUE_VALID_ACCOUNTS
    return MITRE_TACTIC_PRIVILEGE_ESCALATION, MITRE_TECHNIQUE_VALID_ACCOUNTS


def _build_attack_summary(attack_events: Sequence[TimelineEvent]) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = []
    for event in attack_events:
        label = str((event.metadata or {}).get("attack_stage_label", ""))
        if not label or event.event_type == LOGOUT:
            continue
        if label == "VPN Access":
            short = "VPN"
        elif label == "Role / Group Modification":
            short = "Domain Admin"
        elif label == "Privilege Escalation":
            short = "Privilege Escalation"
        elif label == "Admin Portal":
            short = "Admin Portal"
        elif label == "Sensitive Configuration Access":
            short = "Security Policies"
        else:
            short = label.replace(" Access", "").strip()
        if short and short not in stages:
            stages.append(short)
    return " → ".join(stages) if stages else "Privilege Escalation"


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent]) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = ["new_device", "new_browser", "privilege_escalation"]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]

    if any(label == "Admin Portal" for label in labels):
        indicators.append("admin_access")
    if any(label == "Privilege Escalation" for label in labels):
        indicators.append("role_change")
    if any(label == "Role / Group Modification" for label in labels):
        indicators.append("group_membership_change")
    if any(
        label in {"Sensitive Configuration Access", "Security Policies"}
        for label in labels
    ):
        indicators.append("policy_access")
    if any(
        label
        in {
            "AWS Console",
            "Azure Portal",
            "Finance Database",
            "Payroll",
            "Domain Controller",
            "IAM Dashboard",
            "Kubernetes Cluster",
            "Production Servers",
        }
        for label in labels
    ):
        indicators.append("high_privilege_access")
    if any(label == "Mass Download" for label in labels):
        indicators.append("mass_download")
    return indicators


def _build_risk_indicators(
    *,
    plan: _AttackPlan,
    stage_label: str,
) -> list[str]:
    """Assemble explainability-friendly risk indicators for one attack event."""
    indicators = [
        "Privilege Escalation",
        "New Device",
        "New Browser",
        "New Operating System",
        stage_label,
    ]

    if stage_label in {"Admin Portal", "Privilege Escalation"}:
        indicators.extend(["Administrator Access", "Role Changed"])
    if stage_label == "Role / Group Modification":
        indicators.extend(["Role Changed", "Domain Admin", f"Group:{plan.admin_group}"])
    if stage_label == "Sensitive Configuration Access":
        indicators.append("Policy Modification")
    if stage_label == "Mass Download":
        indicators.append("Mass Download")
    if stage_label in {
        "AWS Console",
        "Azure Portal",
        "Finance Database",
        "Payroll",
        "Customer Database",
        "Source Code Repository",
        "Active Directory",
        "Domain Controller",
        "IAM Dashboard",
        "Kubernetes Cluster",
        "Production Servers",
        "Security Policies",
    }:
        indicators.append("Sensitive Resource Access")

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


def _is_escalation_stage(stage_label: str) -> bool:
    """Return True for stages that carry privilege-change metadata."""
    return stage_label in {
        "Admin Portal",
        "Privilege Escalation",
        "Role / Group Modification",
    }


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
    mitre_tactic, mitre_technique = _mitre_for_stage(stage_label, event_type)
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.PRIVILEGE_ESCALATION.value,
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
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "attack_confidence": plan.attack_confidence,
        "role_before": plan.role_before,
        "role_after": plan.role_assigned,
        "admin_group": plan.admin_group,
        "privilege_level": "High",
        "permission_change": "Granted" if _is_escalation_stage(stage_label) else "Used",
        "escalation_time": plan.escalation_time.isoformat(sep=" "),
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
    """Build a privilege-abuse activity burst inside an existing session."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start

    for stage_index, (event_type, resource_id, stage_label) in enumerate(
        plan.resource_sequence
    ):
        if stage_index > 0:
            cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))

        if stage_label == "Privilege Escalation":
            plan.escalation_time = cursor

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

    # Attacker disconnects last.
    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
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
    escalation_iso = plan.escalation_time.isoformat(sep=" ")
    for event in generated:
        event.metadata["escalation_time"] = escalation_iso
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type
        event.metadata["role_before"] = plan.role_before
        event.metadata["role_after"] = plan.role_assigned
        event.metadata["admin_group"] = plan.admin_group

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
    """Validate integrity of the injected Privilege Escalation burst."""
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

    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    if "Admin Portal" not in labels:
        return False
    if "Privilege Escalation" not in labels:
        return False
    if "Role / Group Modification" not in labels:
        return False
    if "Mass Download" not in labels:
        return False

    admin_index = labels.index("Admin Portal")
    escalation_index = labels.index("Privilege Escalation")
    role_index = labels.index("Role / Group Modification")
    if not (admin_index < escalation_index < role_index):
        return False

    if plan.include_vpn:
        if "VPN Access" not in labels:
            return False
        if labels.index("VPN Access") > admin_index:
            return False

    # Metadata completeness across the injected burst.
    for event in attack_events:
        metadata = event.metadata or {}
        if any(key not in metadata for key in REQUIRED_METADATA_KEYS):
            return False
        if metadata.get("role_after") != plan.role_assigned:
            return False
        if metadata.get("admin_group") != plan.admin_group:
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
    """Build a fully populated AttackRecord for the Privilege Escalation case."""
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
        "escalation_time": plan.escalation_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "role_before": plan.role_before,
        "role_granted": plan.role_assigned,
        "admin_group": plan.admin_group,
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
        "include_vpn": plan.include_vpn,
        "accessed_resources": accessed_resources,
        "modified_event_ids": [event.event_id for event in attack_events],
        "number_of_inserted_events": len(attack_events),
    }
    description = (
        f"Privilege escalation: elevated {plan.role_before} to {plan.role_assigned} "
        f"({plan.admin_group}) via admin portal abuse, then accessed "
        f"{', '.join(accessed_resources) if accessed_resources else 'none'} "
        f"using {plan.authentication_type} from {persona.device_id} "
        f"({persona.user_agent}) via {plan.location_id} [{persona.source_ip}] "
        f"confidence={plan.attack_confidence} duration={attack_duration_seconds}s. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = (
        target.severity if isinstance(target.severity, Severity) else Severity.CRITICAL
    )

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
