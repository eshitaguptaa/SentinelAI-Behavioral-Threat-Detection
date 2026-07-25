"""Lateral Movement attack technique.

Injects a realistic post-compromise network-pivot burst into one existing
employee session: internal discovery, remote host access, admin share use,
remote execution, credential reuse, and hops onto additional servers before
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

ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (30, 140)

# Offset after the legitimate login before pivoting begins.
ATTACK_START_OFFSET_MINUTES: Final[tuple[int, int]] = (10, 50)
# Room for discovery → hops → credential reuse → sensitive access → logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 40

MIN_TARGET_HOSTS: Final[int] = 3
MAX_TARGET_HOSTS: Final[int] = 5

COMPROMISE_METHOD: Final[str] = "Lateral Movement"

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
    "Cached Domain Credentials",
    "NTLM Hash",
)

ORIGIN_HOSTS: Final[tuple[str, ...]] = (
    "WS-001",
    "WS-014",
    "LAPTOP-042",
    "ENG-PC-19",
)

INTERNAL_HOSTS: Final[tuple[str, ...]] = (
    "WS-021",
    "WS-144",
    "HR-PC-07",
    "FIN-DB-01",
    "APP-SRV-03",
    "WEB-SRV-02",
    "DC-01",
    "DC-02",
    "SQL-01",
    "BACKUP-01",
    "MAIL-01",
    "FILE-SRV-04",
)

SENSITIVE_HOSTS: Final[frozenset[str]] = frozenset(
    {"DC-01", "DC-02", "FIN-DB-01", "SQL-01", "BACKUP-01", "MAIL-01"}
)

DOMAIN_CONTROLLERS: Final[frozenset[str]] = frozenset({"DC-01", "DC-02"})

PROTOCOLS: Final[tuple[str, ...]] = (
    "RDP",
    "SMB",
    "WinRM",
    "SSH",
    "PsExec",
    "WMI",
)

PROTOCOL_TO_TOOL: Final[dict[str, str]] = {
    "RDP": "Remote Desktop",
    "SMB": "SMB Share",
    "WinRM": "PowerShell",
    "SSH": "SSH Client",
    "PsExec": "PsExec",
    "WMI": "WMIC",
}

PROTOCOL_TO_RESOURCE: Final[dict[str, str]] = {
    "RDP": "RES-REMOTE_DESKTOP",
    "SMB": "RES-ADMIN_SHARE",
    "WinRM": "RES-WINRM",
    "SSH": "RES-SSH",
    "PsExec": "RES-PSEXEC",
    "WMI": "RES-WMI",
}

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

MITRE_TACTIC_DISCOVERY: Final[str] = "Discovery"
MITRE_TACTIC_LATERAL_MOVEMENT: Final[str] = "Lateral Movement"
MITRE_TACTIC_CREDENTIAL_ACCESS: Final[str] = "Credential Access"

MITRE_TECHNIQUE_NETWORK_SERVICE_DISCOVERY: Final[str] = "Network Service Discovery"
MITRE_TECHNIQUE_REMOTE_SERVICES: Final[str] = "Remote Services"
MITRE_TECHNIQUE_SMB_ADMIN_SHARES: Final[str] = "SMB/Windows Admin Shares"
MITRE_TECHNIQUE_REMOTE_DESKTOP: Final[str] = "Remote Desktop Protocol"
MITRE_TECHNIQUE_WINRM: Final[str] = "Windows Remote Management"
MITRE_TECHNIQUE_SSH: Final[str] = "SSH"
MITRE_TECHNIQUE_SESSION_HIJACKING: Final[str] = "Remote Service Session Hijacking"
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
    """Candidate legitimate session selected for lateral movement."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed lateral-movement geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    discovery_time: datetime
    pivot_time: datetime
    credential_reuse_time: datetime
    authentication_type: str
    attack_confidence: float
    location_id: str
    origin_location: str
    origin_host: str
    target_hosts: tuple[str, ...]
    resource_sequence: tuple[tuple[str, str, str, str], ...]
    protocol: str
    remote_tool: str


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
    """Inject a Lateral Movement compromise for a single attack target.

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
    """Return True when the employee is eligible for Lateral Movement."""
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
    """Count prior Lateral Movement markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.LATERAL_MOVEMENT.value
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


def _select_target_hosts(rng: random.Random) -> tuple[str, ...]:
    """Choose a deterministic set of internal hosts for pivoting."""
    count = rng.randint(MIN_TARGET_HOSTS, MAX_TARGET_HOSTS)
    pool = list(INTERNAL_HOSTS)
    rng.shuffle(pool)
    selected = pool[:count]

    # Prefer at least one sensitive system in the hop path.
    if not any(host in SENSITIVE_HOSTS for host in selected):
        selected[-1] = rng.choice(tuple(SENSITIVE_HOSTS))
    return tuple(dict.fromkeys(selected))


def _build_resource_sequence(
    *,
    origin_host: str,
    target_hosts: Sequence[str],
    protocol: str,
) -> tuple[tuple[str, str, str, str], ...]:
    """Assemble ordered lateral-movement stages.

    Each tuple is ``(event_type, resource_id, stage_label, target_host)``.
    """
    resource_id = PROTOCOL_TO_RESOURCE[protocol]
    sequence: list[tuple[str, str, str, str]] = [
        (
            APPLICATION_ACCESS,
            "RES-NETWORK_SCANNER",
            "Internal Network Discovery",
            origin_host,
        )
    ]

    first_host = target_hosts[0]
    sequence.append(
        (
            APPLICATION_ACCESS,
            resource_id,
            f"Remote System Access ({first_host})",
            first_host,
        )
    )
    sequence.append(
        (
            FILE_ACCESS,
            "RES-ADMIN_SHARE",
            f"Admin Share Access ({first_host})",
            first_host,
        )
    )
    sequence.append(
        (
            APPLICATION_ACCESS,
            resource_id,
            f"Remote Command Execution ({first_host})",
            first_host,
        )
    )
    sequence.append(
        (
            RESOURCE_ACCESS,
            "RES-CREDENTIAL_STORE",
            "Credential Reuse",
            first_host,
        )
    )

    remaining = list(target_hosts[1:])
    if not remaining:
        remaining = [_fallback_alternate_host(first_host)]

    second_host = remaining[0]
    sequence.append(
        (
            APPLICATION_ACCESS,
            resource_id,
            f"Internal Server Hop ({second_host})",
            second_host,
        )
    )

    sensitive = next(
        (host for host in target_hosts if host in SENSITIVE_HOSTS),
        remaining[-1],
    )
    if sensitive == second_host and len(remaining) > 1:
        sensitive = remaining[-1]
    sequence.append(
        (
            RESOURCE_ACCESS,
            "RES-SENSITIVE_SERVER",
            f"Sensitive Server Access ({sensitive})",
            sensitive,
        )
    )
    return tuple(sequence)


def _fallback_alternate_host(exclude: str) -> str:
    """Pick a deterministic alternate host when the selection is too short."""
    for host in INTERNAL_HOSTS:
        if host != exclude:
            return host
    return "APP-SRV-03"


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive pivot timing, protocol, hosts, and stage ordering."""
    offset_minutes = rng.randint(*ATTACK_START_OFFSET_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=offset_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None

    origin_host = rng.choice(ORIGIN_HOSTS)
    target_hosts = _select_target_hosts(rng)
    protocol = rng.choice(PROTOCOLS)
    remote_tool = PROTOCOL_TO_TOOL[protocol]
    resource_sequence = _build_resource_sequence(
        origin_host=origin_host,
        target_hosts=target_hosts,
        protocol=protocol,
    )

    approx_gap = (ACTIVITY_GAP_SECONDS[0] + ACTIVITY_GAP_SECONDS[1]) // 2
    discovery_time = attack_start
    pivot_time = attack_start + timedelta(seconds=approx_gap)
    credential_reuse_time = attack_start + timedelta(seconds=4 * approx_gap)

    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        discovery_time=discovery_time,
        pivot_time=pivot_time,
        credential_reuse_time=credential_reuse_time,
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        origin_host=origin_host,
        target_hosts=target_hosts,
        resource_sequence=resource_sequence,
        protocol=protocol,
        remote_tool=remote_tool,
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
        f"DEV-PIVOT-{serial % 1000:03d}",
        f"DEV-JUMP-{serial % 10000:04d}",
        f"DEV-LAT-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 17) % 1_000_000:06d}"


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


def _mitre_for_stage(stage_label: str, protocol: str) -> tuple[str, str]:
    """Map an attack stage to MITRE ATT&CK tactic/technique."""
    if stage_label == "Internal Network Discovery":
        return MITRE_TACTIC_DISCOVERY, MITRE_TECHNIQUE_NETWORK_SERVICE_DISCOVERY
    if stage_label == "Credential Reuse":
        return MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_VALID_ACCOUNTS
    if "Admin Share" in stage_label:
        return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SMB_ADMIN_SHARES
    if "Remote Command Execution" in stage_label:
        return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_REMOTE_SERVICES
    if "Remote System Access" in stage_label or "Internal Server Hop" in stage_label:
        if protocol == "RDP":
            return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_REMOTE_DESKTOP
        if protocol == "WinRM":
            return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_WINRM
        if protocol == "SSH":
            return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SSH
        if protocol == "SMB":
            return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SMB_ADMIN_SHARES
        return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_REMOTE_SERVICES
    if "Sensitive Server Access" in stage_label:
        return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SESSION_HIJACKING
    return MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_REMOTE_SERVICES


def _build_attack_summary(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = []
    for event in attack_events:
        label = str((event.metadata or {}).get("attack_stage_label", ""))
        if not label or event.event_type == LOGOUT:
            continue
        if label == "Internal Network Discovery":
            short = "Network Discovery"
        elif label.startswith("Remote System Access"):
            short = (event.metadata or {}).get("target_host", plan.target_hosts[0])
        elif label.startswith("Admin Share Access"):
            short = plan.protocol
        elif label == "Credential Reuse":
            short = "Credential Reuse"
        elif label.startswith("Internal Server Hop"):
            short = (event.metadata or {}).get("target_host", "Internal Server")
        elif label.startswith("Sensitive Server Access"):
            host = str((event.metadata or {}).get("target_host", ""))
            short = "Domain Controller" if host in DOMAIN_CONTROLLERS else host or "Sensitive Server"
        elif label.startswith("Remote Command Execution"):
            continue
        else:
            short = label
        if short and short not in stages:
            stages.append(str(short))
    return " → ".join(stages) if stages else "Lateral Movement"


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = ["lateral_movement", "internal_scan", "network_discovery"]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]
    hosts = {
        str((event.metadata or {}).get("target_host", ""))
        for event in attack_events
        if (event.metadata or {}).get("target_host")
    }

    if any(label.startswith("Remote System Access") for label in labels):
        indicators.append("remote_login")
    if len(hosts) >= 2:
        indicators.append("multiple_hosts")
    if "Credential Reuse" in labels:
        indicators.append("credential_reuse")
    if any("Admin Share" in label for label in labels):
        indicators.append("admin_share")
    if any("Remote Command Execution" in label for label in labels):
        indicators.append("remote_execution")
    if any(host in DOMAIN_CONTROLLERS for host in hosts):
        indicators.append("domain_controller_access")
    if plan.protocol:
        indicators.append("internal_scan")

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
        "Lateral Movement",
        "New Device",
        "Internal Network",
        stage_label,
    ]

    if stage_label.startswith("Remote System Access") or stage_label.startswith("Internal Server Hop"):
        indicators.extend(["Remote Login", "Multiple Hosts"])
    if "Admin Share" in stage_label:
        indicators.append("Admin Share")
    if "Remote Command Execution" in stage_label:
        indicators.append("Remote Execution")
    if stage_label == "Credential Reuse":
        indicators.append("Credential Reuse")
    if "Sensitive Server Access" in stage_label:
        indicators.extend(["Multiple Hosts", "Remote Login"])
    if plan.protocol:
        indicators.append(f"Protocol:{plan.protocol}")

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


def _stage_lateral_fields(
    *,
    stage_label: str,
    target_host: str,
    plan: _AttackPlan,
    lateral_hop: int,
) -> dict[str, object]:
    """Build stage-specific lateral-movement metadata fields."""
    return {
        "origin_host": plan.origin_host,
        "target_host": target_host,
        "protocol": plan.protocol,
        "remote_tool": plan.remote_tool,
        "credential_reuse": stage_label == "Credential Reuse",
        "session_clone": "Remote System Access" in stage_label
        or "Internal Server Hop" in stage_label,
        "remote_execution": "Remote Command Execution" in stage_label,
        "internal_network": True,
        "lateral_hop": lateral_hop,
        "admin_share": "Admin Share" in stage_label,
    }


def _append_event(
    *,
    generated: list[TimelineEvent],
    cursor: datetime,
    event_type: str,
    resource_id: str | None,
    stage_label: str,
    stage_index: int,
    target_host: str,
    lateral_hop: int,
    result: str,
    session: _SessionSlice,
    plan: _AttackPlan,
    persona: _AttackerPersona,
    attack_id: str,
    target: AttackTarget,
    id_factory: Callable[[], str],
) -> datetime:
    """Materialize one attack event and return its timestamp."""
    mitre_tactic, mitre_technique = _mitre_for_stage(stage_label, plan.protocol)
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.LATERAL_MOVEMENT.value,
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
        "discovery_time": plan.discovery_time.isoformat(sep=" "),
        "pivot_time": plan.pivot_time.isoformat(sep=" "),
        "credential_reuse_time": plan.credential_reuse_time.isoformat(sep=" "),
        "simulation_date": target.day.isoformat(),
        "work_mode": "attack",
    }
    metadata.update(
        _stage_lateral_fields(
            stage_label=stage_label,
            target_host=target_host,
            plan=plan,
            lateral_hop=lateral_hop,
        )
    )

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
    """Build an internal discovery and host-pivot activity burst."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start
    hop_counter = 0

    for stage_index, (event_type, resource_id, stage_label, target_host) in enumerate(
        plan.resource_sequence
    ):
        if stage_index > 0:
            cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))

        if stage_label == "Internal Network Discovery":
            plan.discovery_time = cursor
            lateral_hop = 0
        elif stage_label.startswith("Remote System Access"):
            plan.pivot_time = cursor
            hop_counter += 1
            lateral_hop = hop_counter
        elif stage_label == "Credential Reuse":
            plan.credential_reuse_time = cursor
            lateral_hop = hop_counter
        elif stage_label.startswith("Internal Server Hop") or stage_label.startswith(
            "Sensitive Server Access"
        ):
            hop_counter += 1
            lateral_hop = hop_counter
        else:
            lateral_hop = hop_counter

        cursor = _append_event(
            generated=generated,
            cursor=cursor,
            event_type=event_type,
            resource_id=resource_id,
            stage_label=stage_label,
            stage_index=stage_index,
            target_host=target_host,
            lateral_hop=lateral_hop,
            result="success",
            session=session,
            plan=plan,
            persona=persona,
            attack_id=attack_id,
            target=target,
            id_factory=id_factory,
        )

    cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))
    _append_event(
        generated=generated,
        cursor=cursor,
        event_type=LOGOUT,
        resource_id=None,
        stage_label="Attacker Logout",
        stage_index=len(plan.resource_sequence),
        target_host=plan.origin_host,
        lateral_hop=hop_counter,
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
    discovery_iso = plan.discovery_time.isoformat(sep=" ")
    pivot_iso = plan.pivot_time.isoformat(sep=" ")
    credential_iso = plan.credential_reuse_time.isoformat(sep=" ")
    for event in generated:
        event.metadata["discovery_time"] = discovery_iso
        event.metadata["pivot_time"] = pivot_iso
        event.metadata["credential_reuse_time"] = credential_iso
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type
        event.metadata["protocol"] = plan.protocol
        event.metadata["remote_tool"] = plan.remote_tool
        event.metadata["origin_host"] = plan.origin_host

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
    """Validate integrity of the injected Lateral Movement burst."""
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
    if "Internal Network Discovery" not in labels:
        return False
    if not any(label.startswith("Remote System Access") for label in labels):
        return False
    if not any("Admin Share" in label for label in labels):
        return False
    if not any("Remote Command Execution" in label for label in labels):
        return False
    if "Credential Reuse" not in labels:
        return False
    if not any(label.startswith("Internal Server Hop") for label in labels):
        return False
    if not any(label.startswith("Sensitive Server Access") for label in labels):
        return False

    discovery_index = labels.index("Internal Network Discovery")
    remote_index = next(
        index for index, label in enumerate(labels) if label.startswith("Remote System Access")
    )
    admin_index = next(index for index, label in enumerate(labels) if "Admin Share" in label)
    exec_index = next(
        index for index, label in enumerate(labels) if "Remote Command Execution" in label
    )
    cred_index = labels.index("Credential Reuse")
    hop_index = next(
        index for index, label in enumerate(labels) if label.startswith("Internal Server Hop")
    )
    sensitive_index = next(
        index
        for index, label in enumerate(labels)
        if label.startswith("Sensitive Server Access")
    )
    if not (
        discovery_index
        < remote_index
        < admin_index
        < exec_index
        < cred_index
        < hop_index
        < sensitive_index
    ):
        return False

    for event in attack_events:
        metadata = event.metadata or {}
        if any(key not in metadata for key in REQUIRED_METADATA_KEYS):
            return False
        if metadata.get("protocol") != plan.protocol:
            return False
        if metadata.get("remote_tool") != plan.remote_tool:
            return False
        if metadata.get("origin_host") != plan.origin_host:
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
    """Build a fully populated AttackRecord for the Lateral Movement case."""
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
        "discovery_time": plan.discovery_time.isoformat(sep=" "),
        "pivot_time": plan.pivot_time.isoformat(sep=" "),
        "credential_reuse_time": plan.credential_reuse_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "origin_host": plan.origin_host,
        "target_hosts": list(plan.target_hosts),
        "protocol": plan.protocol,
        "remote_tool": plan.remote_tool,
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
        "accessed_resources": accessed_resources,
        "modified_event_ids": [event.event_id for event in attack_events],
        "number_of_inserted_events": len(attack_events),
    }
    description = (
        f"Lateral movement: pivoted from {plan.origin_host} across "
        f"{', '.join(plan.target_hosts)} using {plan.protocol}/{plan.remote_tool} "
        f"with {plan.authentication_type} from {persona.device_id} "
        f"({persona.user_agent}) via {plan.location_id} [{persona.source_ip}] "
        f"confidence={plan.attack_confidence} duration={attack_duration_seconds}s. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = (
        target.severity if isinstance(target.severity, Severity) else Severity.HIGH
    )

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.LATERAL_MOVEMENT,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
