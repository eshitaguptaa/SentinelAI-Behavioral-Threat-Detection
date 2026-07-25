"""Data Exfiltration attack technique.

Injects a realistic post-compromise data-theft burst into one existing employee
session: sensitive file discovery, staged collection, bulk download, archive
creation, then upload to an external cloud destination before logout.
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

ACTIVITY_GAP_SECONDS: Final[tuple[int, int]] = (35, 150)

# Offset after the legitimate login before collection begins.
ATTACK_START_OFFSET_MINUTES: Final[tuple[int, int]] = (15, 60)
# Room for discovery → collection → archive → upload → logout.
ATTACK_BURST_BUFFER_MINUTES: Final[int] = 40

MIN_SENSITIVE_SOURCES: Final[int] = 2
MAX_SENSITIVE_SOURCES: Final[int] = 4
MIN_FILE_ACCESSES: Final[int] = 2
MAX_FILE_ACCESSES: Final[int] = 4

MIN_TOTAL_FILES: Final[int] = 25
MAX_TOTAL_FILES: Final[int] = 480
MIN_DATA_SIZE_MB: Final[int] = 45
MAX_DATA_SIZE_MB: Final[int] = 2500

COMPROMISE_METHOD: Final[str] = "Data Exfiltration"

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

COMPRESSION_FORMATS: Final[tuple[str, ...]] = ("ZIP", "RAR", "7Z", "TAR.GZ")

CLOUD_PROVIDERS: Final[tuple[str, ...]] = (
    "Dropbox",
    "Google Drive",
    "OneDrive",
    "Mega",
    "AWS S3",
    "Azure Blob",
    "External FTP",
)

CLOUD_UPLOAD_DESTINATIONS: Final[dict[str, str]] = {
    "Dropbox": "dropbox.com/home/exfil",
    "Google Drive": "drive.google.com/drive/u/0/folders/exfil",
    "OneDrive": "onedrive.live.com/exfil",
    "Mega": "mega.nz/folder/exfil",
    "AWS S3": "s3://exfil-bucket-private/staging",
    "Azure Blob": "https://exfilstore.blob.core.windows.net/staging",
    "External FTP": "ftp://files.external-transfer.net/inbox",
}

ARCHIVE_NAME_TEMPLATES: Final[tuple[str, ...]] = (
    "finance_backup.{ext}",
    "contracts_2026.{ext}",
    "engineering_docs.{ext}",
    "hr_export_{serial}.{ext}",
    "customer_dump_{serial}.{ext}",
    "legal_bundle.{ext}",
    "prod_backup_{serial}.{ext}",
)

COMPRESSION_EXTENSIONS: Final[dict[str, str]] = {
    "ZIP": "zip",
    "RAR": "rar",
    "7Z": "7z",
    "TAR.GZ": "tar.gz",
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

MITRE_TACTIC_COLLECTION: Final[str] = "Collection"
MITRE_TACTIC_EXFILTRATION: Final[str] = "Exfiltration"
MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM: Final[str] = "Data from Local System"
MITRE_TECHNIQUE_DATA_STAGED: Final[str] = "Data Staged"
MITRE_TECHNIQUE_ARCHIVE_COLLECTED_DATA: Final[str] = "Archive Collected Data"
MITRE_TECHNIQUE_EXFIL_OVER_WEB_SERVICE: Final[str] = "Exfiltration Over Web Service"
MITRE_TECHNIQUE_EXFIL_OVER_ALT_PROTOCOL: Final[str] = "Exfiltration Over Alternative Protocol"

DISCOVERY_ACTION: Final[tuple[str, str, str]] = (
    APPLICATION_ACCESS,
    "RES-CLOUD_STORAGE",
    "Sensitive File Discovery",
)
DATABASE_ACTION: Final[tuple[str, str, str]] = (
    RESOURCE_ACCESS,
    "RES-FINANCE_DATABASE",
    "Database Access",
)
BULK_DOWNLOAD_ACTION: Final[tuple[str, str, str]] = (
    FILE_ACCESS,
    "RES-CLOUD_STORAGE",
    "Bulk Download",
)
ARCHIVE_ACTION: Final[tuple[str, str, str]] = (
    FILE_ACCESS,
    "RES-CLOUD_STORAGE",
    "Archive / Compression",
)

# Gradual collection targets before bulk exfiltration.
SENSITIVE_DATA_SOURCES: Final[tuple[tuple[str, str, str], ...]] = (
    (RESOURCE_ACCESS, "RES-FINANCE_DATABASE", "Finance Database"),
    (RESOURCE_ACCESS, "RES-PAYROLL", "Payroll"),
    (RESOURCE_ACCESS, "RES-HR_PORTAL", "HR Records"),
    (FILE_ACCESS, "RES-CRM", "Customer Database"),
    (APPLICATION_ACCESS, "RES-CRM", "CRM"),
    (FILE_ACCESS, "RES-SOURCE_CODE_REPOSITORY", "Source Code Repository"),
    (FILE_ACCESS, "RES-LEGAL_DOCUMENTS", "Legal Documents"),
    (FILE_ACCESS, "RES-CONTRACTS", "Contracts"),
    (FILE_ACCESS, "RES-ENGINEERING_DESIGNS", "Engineering Designs"),
    (FILE_ACCESS, "RES-PRODUCTION_BACKUPS", "Production Backups"),
    (FILE_ACCESS, "RES-MEDICAL_RECORDS", "Medical Records"),
    (APPLICATION_ACCESS, "RES-CLOUD_STORAGE", "Cloud Storage"),
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
    """Candidate legitimate session selected for data exfiltration."""

    session_id: str
    events: list[TimelineEvent]
    login_event: TimelineEvent
    logout_event: TimelineEvent | None


@dataclass(slots=True)
class _AttackPlan:
    """Computed data-exfiltration geometry before events are materialized."""

    attack_start: datetime
    session_start: datetime
    discovery_time: datetime
    compression_time: datetime
    upload_time: datetime
    authentication_type: str
    attack_confidence: float
    location_id: str
    origin_location: str
    resource_sequence: tuple[tuple[str, str, str], ...]
    compression_format: str
    archive_name: str
    cloud_provider: str
    upload_destination: str
    total_files: int
    estimated_data_size_mb: int
    encryption: str


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
    """Inject a Data Exfiltration compromise for a single attack target.

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
    """Return True when the employee is eligible for Data Exfiltration."""
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
    """Count prior Data Exfiltration markers on the employee timeline."""
    return sum(
        1
        for event in employee_events
        if (event.metadata or {}).get("attack_type") == AttackType.DATA_EXFILTRATION.value
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


def _select_sensitive_sources(
    rng: random.Random,
) -> tuple[tuple[str, str, str], ...]:
    """Choose a deterministic subset of sensitive enterprise data sources."""
    count = rng.randint(MIN_SENSITIVE_SOURCES, MAX_SENSITIVE_SOURCES)
    pool = list(SENSITIVE_DATA_SOURCES)
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


def _select_file_accesses(
    rng: random.Random,
    sources: Sequence[tuple[str, str, str]],
) -> tuple[tuple[str, str, str], ...]:
    """Create gradual sensitive file-access steps from chosen sources."""
    count = rng.randint(MIN_FILE_ACCESSES, MAX_FILE_ACCESSES)
    accesses: list[tuple[str, str, str]] = []
    for index in range(count):
        event_type, resource_id, label = sources[index % len(sources)]
        # Prefer FILE_ACCESS for discovery browsing even when the source is a DB.
        access_type = FILE_ACCESS if event_type != APPLICATION_ACCESS else FILE_ACCESS
        accesses.append(
            (
                access_type,
                resource_id,
                f"Sensitive File Access ({label})",
            )
        )
    return tuple(accesses)


def _build_archive_name(
    *,
    compression_format: str,
    cloud_serial: int,
    rng: random.Random,
) -> str:
    """Build a believable staged archive filename."""
    extension = COMPRESSION_EXTENSIONS[compression_format]
    template = rng.choice(ARCHIVE_NAME_TEMPLATES)
    return template.format(ext=extension, serial=cloud_serial % 1000)


def _cloud_upload_action(cloud_provider: str) -> tuple[str, str, str]:
    """Map a cloud provider to an upload stage event."""
    resource_map = {
        "Dropbox": "RES-DROPBOX",
        "Google Drive": "RES-GOOGLE_DRIVE",
        "OneDrive": "RES-ONEDRIVE",
        "Mega": "RES-MEGA",
        "AWS S3": "RES-AWS_CONSOLE",
        "Azure Blob": "RES-AZURE_PORTAL",
        "External FTP": "RES-EXTERNAL_FTP",
    }
    return (
        APPLICATION_ACCESS,
        resource_map.get(cloud_provider, "RES-CLOUD_STORAGE"),
        f"{cloud_provider} Upload",
    )


def _build_resource_sequence(
    rng: random.Random,
    *,
    cloud_provider: str,
) -> tuple[tuple[str, str, str], ...]:
    """Assemble the ordered collection → staging → exfiltration spine."""
    sources = _select_sensitive_sources(rng)
    sequence: list[tuple[str, str, str]] = [DISCOVERY_ACTION]
    sequence.extend(_select_file_accesses(rng, sources))

    # Prefer an explicit database hop when finance/payroll/hr were selected.
    db_candidates = [
        source
        for source in sources
        if source[2] in {"Finance Database", "Payroll", "HR Records", "Customer Database"}
    ]
    if db_candidates:
        event_type, resource_id, label = rng.choice(db_candidates)
        sequence.append((RESOURCE_ACCESS, resource_id, f"Database Access ({label})"))
    else:
        sequence.append(DATABASE_ACTION)

    sequence.append(BULK_DOWNLOAD_ACTION)
    sequence.append(ARCHIVE_ACTION)
    sequence.append(_cloud_upload_action(cloud_provider))
    return tuple(sequence)


def _build_attack_plan(session: _SessionSlice, rng: random.Random) -> _AttackPlan | None:
    """Derive exfiltration timing, archive details, and resource selections."""
    offset_minutes = rng.randint(*ATTACK_START_OFFSET_MINUTES)
    attack_start = session.login_event.timestamp + timedelta(minutes=offset_minutes)

    session_end = (
        session.logout_event.timestamp
        if session.logout_event is not None
        else session.events[-1].timestamp
    )
    if attack_start + timedelta(minutes=ATTACK_BURST_BUFFER_MINUTES) >= session_end:
        return None

    compression_format = rng.choice(COMPRESSION_FORMATS)
    cloud_provider = rng.choice(CLOUD_PROVIDERS)
    serial = rng.randint(100, 999)
    archive_name = _build_archive_name(
        compression_format=compression_format,
        cloud_serial=serial,
        rng=rng,
    )
    resource_sequence = _build_resource_sequence(rng, cloud_provider=cloud_provider)

    approx_gap = (ACTIVITY_GAP_SECONDS[0] + ACTIVITY_GAP_SECONDS[1]) // 2
    discovery_time = attack_start
    # Estimate later stage times; refined during event generation.
    compression_index = next(
        (
            index
            for index, action in enumerate(resource_sequence)
            if action[2] == "Archive / Compression"
        ),
        max(len(resource_sequence) - 2, 0),
    )
    upload_index = len(resource_sequence) - 1
    compression_time = attack_start + timedelta(seconds=compression_index * approx_gap)
    upload_time = attack_start + timedelta(seconds=upload_index * approx_gap)

    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    return _AttackPlan(
        attack_start=attack_start,
        session_start=session.login_event.timestamp,
        discovery_time=discovery_time,
        compression_time=compression_time,
        upload_time=upload_time,
        authentication_type=rng.choice(AUTHENTICATION_TYPES),
        attack_confidence=attack_confidence,
        location_id=rng.choice(ATTACKER_LOCATIONS),
        origin_location=session.login_event.location_id,
        resource_sequence=resource_sequence,
        compression_format=compression_format,
        archive_name=archive_name,
        cloud_provider=cloud_provider,
        upload_destination=CLOUD_UPLOAD_DESTINATIONS[cloud_provider],
        total_files=rng.randint(MIN_TOTAL_FILES, MAX_TOTAL_FILES),
        estimated_data_size_mb=rng.randint(MIN_DATA_SIZE_MB, MAX_DATA_SIZE_MB),
        encryption=rng.choice(("AES-256", "AES-128", "None")),
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
        f"DEV-EXFIL-{serial % 1000:03d}",
        f"DEV-STAGE-{serial % 10000:04d}",
        f"DEV-SYNC-{serial % 1000:03d}",
    )
    choices = list(templates)
    rng.shuffle(choices)

    for candidate in choices:
        if candidate != victim_device_id:
            return candidate

    return f"DEV-ATTACK-{(serial + 13) % 1_000_000:06d}"


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


def _mitre_for_stage(stage_label: str, cloud_provider: str) -> tuple[str, str]:
    """Map an attack stage to MITRE ATT&CK tactic/technique."""
    if stage_label == "Sensitive File Discovery":
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM
    if stage_label.startswith("Sensitive File Access"):
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM
    if stage_label.startswith("Database Access"):
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM
    if stage_label == "Bulk Download":
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_STAGED
    if stage_label == "Archive / Compression":
        return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_ARCHIVE_COLLECTED_DATA
    if stage_label.endswith("Upload"):
        if cloud_provider == "External FTP":
            return MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_OVER_ALT_PROTOCOL
        return MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_OVER_WEB_SERVICE
    return MITRE_TACTIC_COLLECTION, MITRE_TECHNIQUE_DATA_FROM_LOCAL_SYSTEM


def _build_attack_summary(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> str:
    """Create a compact SOC-facing summary of the injected kill chain."""
    stages: list[str] = []
    for event in attack_events:
        label = str((event.metadata or {}).get("attack_stage_label", ""))
        if not label or event.event_type == LOGOUT:
            continue
        if label == "Sensitive File Discovery":
            short = "Sensitive Files"
        elif label.startswith("Sensitive File Access"):
            continue
        elif label.startswith("Database Access"):
            inner = label.removeprefix("Database Access (").removesuffix(")")
            short = inner if inner != label else "Database Access"
        elif label == "Bulk Download":
            short = "Bulk Download"
        elif label == "Archive / Compression":
            short = f"{plan.compression_format} Archive"
        elif label.endswith("Upload"):
            short = f"{plan.cloud_provider} Upload"
        else:
            short = label
        if short and short not in stages:
            stages.append(short)
    return " → ".join(stages) if stages else "Data Exfiltration"


def _build_ioc_indicators(attack_events: Sequence[TimelineEvent], plan: _AttackPlan) -> list[str]:
    """Collect IOC flags that actually occurred during the attack."""
    indicators: list[str] = ["data_exfiltration", "sensitive_files"]
    labels = [
        str((event.metadata or {}).get("attack_stage_label", ""))
        for event in attack_events
    ]

    if any(label.startswith("Sensitive File Access") for label in labels):
        indicators.append("sensitive_files")
    if any(label.startswith("Database Access") for label in labels):
        indicators.append("database_access")
    if "Bulk Download" in labels:
        indicators.append("bulk_download")
    if "Archive / Compression" in labels:
        indicators.append("archive_creation")
    if any(label.endswith("Upload") for label in labels):
        indicators.extend(["external_upload", "cloud_storage"])
    if plan.estimated_data_size_mb >= 250:
        indicators.extend(["large_transfer", "high_data_volume"])
    elif plan.estimated_data_size_mb >= 100:
        indicators.append("large_transfer")

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
        "Data Exfiltration",
        "New Device",
        "New Browser",
        "Sensitive Data",
        stage_label,
    ]

    if stage_label.startswith("Sensitive File Access") or stage_label == "Sensitive File Discovery":
        indicators.append("Mass File Access")
    if stage_label.startswith("Database Access"):
        indicators.append("Sensitive Data")
    if stage_label == "Bulk Download":
        indicators.extend(["Bulk Download", "Large Data Volume"])
    if stage_label == "Archive / Compression":
        indicators.append("Archive Creation")
    if stage_label.endswith("Upload"):
        indicators.extend(["External Transfer", "Cloud Upload"])
    if plan.estimated_data_size_mb >= 250:
        indicators.append("Large Data Volume")

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


def _stage_exfil_fields(stage_label: str, plan: _AttackPlan) -> dict[str, object]:
    """Build stage-specific exfiltration metadata fields."""
    fields: dict[str, object] = {
        "file_count": plan.total_files,
        "data_size_mb": plan.estimated_data_size_mb,
        "compression": plan.compression_format,
        "archive_name": plan.archive_name,
        "upload_destination": plan.upload_destination,
        "cloud_provider": plan.cloud_provider,
        "external_transfer": stage_label.endswith("Upload"),
        "encryption": plan.encryption,
        "download_type": "bulk" if stage_label == "Bulk Download" else "selective",
    }
    if stage_label == "Sensitive File Discovery":
        fields["download_type"] = "discovery"
    if stage_label.startswith("Sensitive File Access"):
        fields["download_type"] = "selective"
    if stage_label == "Archive / Compression":
        fields["download_type"] = "staged"
    if stage_label.endswith("Upload"):
        fields["download_type"] = "exfiltration"
    return fields


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
    mitre_tactic, mitre_technique = _mitre_for_stage(stage_label, plan.cloud_provider)
    metadata = {
        "attack_id": attack_id,
        "attack_type": AttackType.DATA_EXFILTRATION.value,
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
        "compression_time": plan.compression_time.isoformat(sep=" "),
        "upload_time": plan.upload_time.isoformat(sep=" "),
        "simulation_date": target.day.isoformat(),
        "work_mode": "attack",
    }
    metadata.update(_stage_exfil_fields(stage_label, plan))

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
    """Build a gradual collection and exfiltration burst."""
    generated: list[TimelineEvent] = []
    cursor = plan.attack_start

    for stage_index, (event_type, resource_id, stage_label) in enumerate(
        plan.resource_sequence
    ):
        if stage_index > 0:
            cursor += timedelta(seconds=rng.randint(*ACTIVITY_GAP_SECONDS))

        if stage_label == "Sensitive File Discovery":
            plan.discovery_time = cursor
        elif stage_label == "Archive / Compression":
            plan.compression_time = cursor
        elif stage_label.endswith("Upload"):
            plan.upload_time = cursor

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

    attack_summary = _build_attack_summary(generated, plan)
    ioc = _build_ioc_indicators(generated, plan)
    attack_duration_seconds = int(
        (generated[-1].timestamp - generated[0].timestamp).total_seconds()
    )
    discovery_iso = plan.discovery_time.isoformat(sep=" ")
    compression_iso = plan.compression_time.isoformat(sep=" ")
    upload_iso = plan.upload_time.isoformat(sep=" ")
    for event in generated:
        event.metadata["discovery_time"] = discovery_iso
        event.metadata["compression_time"] = compression_iso
        event.metadata["upload_time"] = upload_iso
        event.metadata["attack_summary"] = attack_summary
        event.metadata["ioc"] = list(ioc)
        event.metadata["attack_duration_seconds"] = attack_duration_seconds
        event.metadata["attack_confidence"] = plan.attack_confidence
        event.metadata["authentication_type"] = plan.authentication_type
        event.metadata["compression"] = plan.compression_format
        event.metadata["archive_name"] = plan.archive_name
        event.metadata["cloud_provider"] = plan.cloud_provider
        event.metadata["upload_destination"] = plan.upload_destination
        event.metadata["file_count"] = plan.total_files
        event.metadata["data_size_mb"] = plan.estimated_data_size_mb

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
    """Validate integrity of the injected Data Exfiltration burst."""
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
    if "Sensitive File Discovery" not in labels:
        return False
    if "Bulk Download" not in labels:
        return False
    if "Archive / Compression" not in labels:
        return False
    if not any(label.endswith("Upload") for label in labels):
        return False
    if not any(label.startswith("Database Access") for label in labels):
        return False

    discovery_index = labels.index("Sensitive File Discovery")
    bulk_index = labels.index("Bulk Download")
    archive_index = labels.index("Archive / Compression")
    upload_index = next(
        index for index, label in enumerate(labels) if label.endswith("Upload")
    )
    if not (discovery_index < bulk_index < archive_index < upload_index):
        return False

    for event in attack_events:
        metadata = event.metadata or {}
        if any(key not in metadata for key in REQUIRED_METADATA_KEYS):
            return False
        if metadata.get("archive_name") != plan.archive_name:
            return False
        if metadata.get("cloud_provider") != plan.cloud_provider:
            return False
        if metadata.get("compression") != plan.compression_format:
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
    """Build a fully populated AttackRecord for the Data Exfiltration case."""
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
        "compression_time": plan.compression_time.isoformat(sep=" "),
        "upload_time": plan.upload_time.isoformat(sep=" "),
        "attack_end": attack_end.isoformat(sep=" "),
        "files_accessed": plan.total_files,
        "estimated_data_size_mb": plan.estimated_data_size_mb,
        "archive_name": plan.archive_name,
        "compression": plan.compression_format,
        "cloud_destination": plan.cloud_provider,
        "upload_destination": plan.upload_destination,
        "encryption": plan.encryption,
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
        f"Data exfiltration: collected ~{plan.total_files} files "
        f"({plan.estimated_data_size_mb} MB), staged as {plan.archive_name} "
        f"({plan.compression_format}), uploaded to {plan.cloud_provider} "
        f"[{plan.upload_destination}] using {plan.authentication_type} from "
        f"{persona.device_id} ({persona.user_agent}) via {plan.location_id} "
        f"[{persona.source_ip}] confidence={plan.attack_confidence} "
        f"duration={attack_duration_seconds}s. "
        f"details={json.dumps(details, sort_keys=True)}"
    )
    severity = (
        target.severity if isinstance(target.severity, Severity) else Severity.CRITICAL
    )

    return AttackRecord(
        attack_id=attack_id,
        employee_id=target.employee_id,
        attack_type=AttackType.DATA_EXFILTRATION,
        severity=severity,
        day=target.day,
        description=description,
        injected_event_ids=[event.event_id for event in attack_events],
        campaign_id=target.campaign_id,
    )
