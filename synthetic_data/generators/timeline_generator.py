"""Normal workday timeline simulation engine.

Generates realistic chronological enterprise behaviour from BehaviorProfiles.
Does not inject attacks or anomalies.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta
from typing import Final

from faker import Faker

from synthetic_data.generators.event_factory import (
    APPLICATION_ACCESS,
    BREAK_END,
    BREAK_START,
    DEVICE_CONNECT,
    EMAIL_ACCESS,
    EventFactory,
    FILE_ACCESS,
    LOGIN,
    LOGOUT,
    MEETING_JOIN,
    RESOURCE_ACCESS,
    TimelineEvent,
    VPN_CONNECT,
    VPN_DISCONNECT,
)
from synthetic_data.generators.session_generator import SessionFactory
from synthetic_data.models import BehaviorProfile, Device, Employee, Session

EMAIL_RESOURCE_ID: Final[str] = "RES-EMAIL"
TEAMS_RESOURCE_ID: Final[str] = "RES-MICROSOFT_TEAMS"
SLACK_RESOURCE_ID: Final[str] = "RES-SLACK"

_EMAIL_HINTS: Final[tuple[str, ...]] = ("EMAIL", "OUTLOOK")
_MEETING_HINTS: Final[tuple[str, ...]] = ("TEAMS", "SLACK")
_FILE_HINTS: Final[tuple[str, ...]] = (
    "CONFLUENCE",
    "KNOWLEDGE",
    "SHAREPOINT",
    "DRIVE",
    "FILE",
)
_DEV_HINTS: Final[tuple[str, ...]] = (
    "GITHUB",
    "GITLAB",
    "JIRA",
    "SOURCE",
    "AWS",
    "AZURE",
)
_FINANCE_HINTS: Final[tuple[str, ...]] = ("PAYROLL", "FINANCE")
_HR_HINTS: Final[tuple[str, ...]] = ("HR_PORTAL", "HR-", "PAYROLL")
_SALES_HINTS: Final[tuple[str, ...]] = ("CRM",)
_COLLAB_HINTS: Final[tuple[str, ...]] = ("TEAMS", "SLACK", "CONFLUENCE")


def _is_vpn(resource_id: str) -> bool:
    return "VPN" in resource_id.upper()


def _is_email(resource_id: str) -> bool:
    return any(hint in resource_id.upper() for hint in _EMAIL_HINTS)


def _is_meeting_resource(resource_id: str) -> bool:
    token = resource_id.upper()
    return any(hint in token for hint in _MEETING_HINTS)


def _choose_location(profile: BehaviorProfile, employee: Employee, faker: Faker) -> str:
    """Pick a normal login location for the workday."""
    candidates = list(profile.normal_login_locations) or list(profile.preferred_locations)
    if employee.office_location_id and employee.office_location_id not in candidates:
        candidates.append(employee.office_location_id)
    if not candidates:
        return "LOC-UNKNOWN"
    return faker.random.choice(candidates)


def _choose_primary_device(
    profile: BehaviorProfile,
    devices_by_id: Mapping[str, Device],
    faker: Faker,
) -> Device | None:
    """Select the employee's primary device for the workday (prefer laptop)."""
    trusted = [
        devices_by_id[device_id]
        for device_id in profile.trusted_devices
        if device_id in devices_by_id
    ]
    if not trusted:
        return None

    laptops = [device for device in trusted if device.device_type == "laptop"]
    pool = laptops or trusted
    return faker.random.choice(pool)


def _choose_browser(profile: BehaviorProfile, device: Device, faker: Faker) -> str:
    """Select a browser consistent with the profile (fallback to device)."""
    if profile.normal_browser_usage:
        return faker.random.choice(profile.normal_browser_usage)
    if device.browser:
        return device.browser
    return "Chrome"


def _choose_os(profile: BehaviorProfile, device: Device, faker: Faker) -> str:
    """Select an OS consistent with the profile (fallback to device)."""
    if profile.normal_operating_systems:
        if device.operating_system in profile.normal_operating_systems:
            return device.operating_system
        return faker.random.choice(profile.normal_operating_systems)
    return device.operating_system or "Windows"


def _sample_login_time(
    work_date: date,
    profile: BehaviorProfile,
    faker: Faker,
) -> datetime:
    """Sample a login timestamp from the profile window with variance."""
    variance_minutes = max(0, int(profile.normal_login_hours_variance) * 60)
    minute = faker.random.randint(0, 59)
    base = datetime(
        work_date.year,
        work_date.month,
        work_date.day,
        int(profile.typical_login_start) % 24,
        minute,
    )
    offset = faker.random.randint(-variance_minutes, variance_minutes)
    return base + timedelta(minutes=offset)


def _compute_logout_time(
    login_time: datetime,
    profile: BehaviorProfile,
    faker: Faker,
) -> datetime:
    """Derive logout from session duration, nudged toward typical end hour."""
    duration_minutes = max(240.0, float(profile.average_session_duration))
    duration_minutes += faker.random.randint(-30, 30)
    duration_minutes = max(240.0, duration_minutes)

    logout_from_duration = login_time + timedelta(minutes=duration_minutes)

    end_hour = int(profile.typical_login_end) % 24
    end_minute = faker.random.randint(0, 59)
    logout_from_window = datetime(
        login_time.year,
        login_time.month,
        login_time.day,
        end_hour,
        end_minute,
    )
    if logout_from_window <= login_time:
        logout_from_window += timedelta(days=1)

    # Prefer a full workday length so event density has room to spread.
    candidates = [logout_from_duration, logout_from_window]
    return max(candidates)


def _classify_work_event(resource_id: str) -> str:
    """Map a business resource to APPLICATION / RESOURCE / FILE access.

    VPN and Email are handled by dedicated event types and must not appear here.
    """
    token = resource_id.upper()
    if _is_vpn(resource_id) or _is_email(resource_id):
        raise ValueError(f"VPN/Email must not use work-access classification: {resource_id}")

    if any(hint in token for hint in _FILE_HINTS):
        return FILE_ACCESS
    if any(hint in token for hint in _DEV_HINTS) or any(
        hint in token for hint in _COLLAB_HINTS
    ):
        return APPLICATION_ACCESS
    if any(
        hint in token
        for hint in (*_FINANCE_HINTS, *_HR_HINTS, *_SALES_HINTS, "PORTAL", "CRM", "DATABASE")
    ):
        return RESOURCE_ACCESS
    return APPLICATION_ACCESS


def _resource_weight(role: str, resource_id: str) -> float:
    """Role-aware weight so different jobs favour different systems."""
    token = resource_id.upper()
    role_key = role.lower()

    if any(key in role_key for key in ("software", "senior engineer", "engineer")):
        if any(hint in token for hint in ("GITHUB", "GITLAB", "SOURCE")):
            return 5.0
        if "JIRA" in token:
            return 3.5
        if "CONFLUENCE" in token:
            return 2.5
        if any(hint in token for hint in ("SLACK", "TEAMS")):
            return 1.5
        return 0.8

    if "security" in role_key:
        if any(hint in token for hint in ("AWS", "AZURE", "VPN")):
            return 4.0
        if any(hint in token for hint in ("SLACK", "TEAMS", "JIRA")):
            return 2.0
        return 1.0

    if "finance" in role_key:
        if any(hint in token for hint in _FINANCE_HINTS):
            return 5.0
        if any(hint in token for hint in ("TEAMS", "EMAIL")):
            return 2.0
        return 0.6

    if "hr" in role_key:
        if any(hint in token for hint in ("HR_PORTAL", "PAYROLL")):
            return 5.0
        if any(hint in token for hint in ("TEAMS", "EMAIL")):
            return 2.0
        return 0.6

    if "sales" in role_key:
        if "CRM" in token:
            return 5.0
        if any(hint in token for hint in ("EMAIL", "TEAMS", "SLACK")):
            return 3.0
        return 0.7

    if "marketing" in role_key:
        if "CRM" in token:
            return 4.0
        if any(hint in token for hint in ("EMAIL", "SLACK", "CONFLUENCE", "TEAMS")):
            return 3.0
        return 0.7

    if role in {"Director", "Manager"}:
        if any(hint in token for hint in ("TEAMS", "EMAIL", "KNOWLEDGE", "VPN")):
            return 3.0
        if any(hint in token for hint in ("JIRA", "CRM", "GITHUB", "FINANCE", "HR")):
            return 2.0
        return 1.2

    if "legal" in role_key:
        if any(hint in token for hint in ("KNOWLEDGE", "FINANCE", "EMAIL", "TEAMS")):
            return 4.0
        return 0.8

    if "operations" in role_key:
        if any(hint in token for hint in ("AWS", "AZURE", "JIRA", "VPN")):
            return 4.0
        if any(hint in token for hint in ("SLACK", "TEAMS")):
            return 2.0
        return 1.0

    return 1.0


def _work_resources(profile: BehaviorProfile) -> list[str]:
    """Business resources eligible for APPLICATION/RESOURCE/FILE access."""
    return [
        resource_id
        for resource_id in profile.usual_resources
        if not _is_vpn(resource_id) and not _is_email(resource_id)
    ]


def _weighted_choice(resources: Sequence[str], role: str, faker: Faker) -> str | None:
    """Pick a resource using role-specific weights."""
    if not resources:
        return None
    weights = [_resource_weight(role, resource_id) for resource_id in resources]
    total = sum(weights)
    if total <= 0:
        return faker.random.choice(list(resources))

    pick = faker.random.uniform(0, total)
    cumulative = 0.0
    for resource_id, weight in zip(resources, weights, strict=True):
        cumulative += weight
        if pick <= cumulative:
            return resource_id
    return resources[-1]


def _find_meeting_resource(profile: BehaviorProfile) -> str | None:
    """Return Teams/Slack only — never development resources."""
    for resource_id in profile.usual_resources:
        if _is_meeting_resource(resource_id):
            return resource_id
    # Canonical collaboration IDs as a safe fallback when present in the catalog.
    for candidate in (TEAMS_RESOURCE_ID, SLACK_RESOURCE_ID):
        if candidate in profile.usual_resources:
            return candidate
    return None


def _email_resource_id(profile: BehaviorProfile) -> str:
    """Always reference the Email resource for EMAIL_ACCESS events."""
    for resource_id in profile.usual_resources:
        if _is_email(resource_id):
            return resource_id
    return EMAIL_RESOURCE_ID


def _vpn_resource_id(profile: BehaviorProfile) -> str | None:
    """Resolve VPN resource for VPN_CONNECT / VPN_DISCONNECT only."""
    for resource_id in profile.usual_resources:
        if _is_vpn(resource_id):
            return resource_id
    return "RES-VPN"


def _schedule_lunch(
    login_time: datetime,
    logout_time: datetime,
    faker: Faker,
) -> tuple[datetime, datetime] | None:
    """Place a lunch break between 12:00–14:00 lasting 20–60 minutes."""
    lunch_window_start = datetime(
        login_time.year, login_time.month, login_time.day, 12, 0
    )
    lunch_window_end = datetime(
        login_time.year, login_time.month, login_time.day, 14, 0
    )

    if logout_time <= lunch_window_start or login_time >= lunch_window_end:
        return None

    # Leave enough afternoon work time after lunch before final logout.
    earliest = max(login_time + timedelta(minutes=45), lunch_window_start)
    latest = min(logout_time - timedelta(minutes=60), lunch_window_end)
    if earliest >= latest:
        return None

    span_minutes = int((latest - earliest).total_seconds() // 60)
    if span_minutes <= 0:
        return None

    start_offset = faker.random.randint(0, span_minutes)
    break_start = earliest + timedelta(minutes=start_offset)
    duration = faker.random.randint(20, 60)
    break_end = break_start + timedelta(minutes=duration)

    if break_end >= logout_time - timedelta(minutes=30):
        break_end = logout_time - timedelta(minutes=30)
    if break_end <= break_start:
        return None

    return break_start, break_end


def _spread_timestamps(
    start: datetime,
    end: datetime,
    count: int,
    faker: Faker,
) -> list[datetime]:
    """Distribute ``count`` timestamps across ``[start, end)`` with light jitter."""
    if count <= 0:
        return []
    if end <= start:
        return [start for _ in range(count)]

    total_seconds = max(1, int((end - start).total_seconds()))
    timestamps: list[datetime] = []
    for index in range(count):
        # Even spacing with small random jitter.
        center = start + timedelta(seconds=(total_seconds * (index + 1)) / (count + 1))
        jitter = faker.random.randint(-90, 90)
        point = center + timedelta(seconds=jitter)
        if point < start:
            point = start + timedelta(seconds=index)
        if point >= end:
            point = end - timedelta(seconds=(count - index))
        timestamps.append(point)

    timestamps.sort()
    # Enforce strict monotonic order.
    for index in range(1, len(timestamps)):
        if timestamps[index] <= timestamps[index - 1]:
            timestamps[index] = timestamps[index - 1] + timedelta(seconds=30)
    return timestamps


def _emit_work_activity(
    *,
    event_factory: EventFactory,
    timestamp: datetime,
    profile: BehaviorProfile,
    employee: Employee,
    work_pool: Sequence[str],
    meeting_resource: str | None,
    email_resource: str,
    common: dict[str, str | None],
    faker: Faker,
) -> TimelineEvent:
    """Create one natural work activity event."""
    roll = faker.random.random()

    # Email checks are common for most roles.
    if roll < 0.18:
        return event_factory.create(
            timestamp=timestamp,
            event_type=EMAIL_ACCESS,
            resource_id=email_resource,
            **common,
        )

    # Meetings only on collaboration tools.
    if roll < 0.28 and meeting_resource is not None:
        return event_factory.create(
            timestamp=timestamp,
            event_type=MEETING_JOIN,
            resource_id=meeting_resource,
            **common,
        )

    resource_id = _weighted_choice(work_pool, employee.role, faker)
    if resource_id is None:
        return event_factory.create(
            timestamp=timestamp,
            event_type=EMAIL_ACCESS,
            resource_id=email_resource,
            **common,
        )

    event_type = _classify_work_event(resource_id)
    return event_factory.create(
        timestamp=timestamp,
        event_type=event_type,
        resource_id=resource_id,
        **common,
    )


def _generate_employee_workday(
    *,
    employee: Employee,
    profile: BehaviorProfile,
    devices_by_id: Mapping[str, Device],
    work_date: date,
    event_factory: EventFactory,
    session_factory: SessionFactory,
    faker: Faker,
) -> tuple[list[TimelineEvent], list[Session]]:
    """Generate one normal chronological workday for a single employee.

    Uses a single continuous session: login once, lunch break in-session,
    continue working, logout once at end of day.
    """
    primary_device = _choose_primary_device(profile, devices_by_id, faker)
    if primary_device is None:
        return [], []

    location_id = _choose_location(profile, employee, faker)
    login_time = _sample_login_time(work_date, profile, faker)
    logout_time = _compute_logout_time(login_time, profile, faker)
    if logout_time <= login_time + timedelta(hours=4):
        logout_time = login_time + timedelta(hours=8)

    lunch = _schedule_lunch(login_time, logout_time, faker)

    device = primary_device
    browser = _choose_browser(profile, device, faker)
    operating_system = _choose_os(profile, device, faker)

    session = session_factory.create(
        employee_id=employee.employee_id,
        device_id=device.device_id,
        location_id=location_id,
        login_time=login_time,
        logout_time=logout_time,
        faker=faker,
    )

    common: dict[str, str | None] = {
        "employee_id": employee.employee_id,
        "device_id": device.device_id,
        "location_id": location_id,
        "session_id": session.session_id,
        "browser": browser,
        "operating_system": operating_system,
    }

    work_pool = _work_resources(profile)
    meeting_resource = _find_meeting_resource(profile)
    email_resource = _email_resource_id(profile)
    vpn_resource = _vpn_resource_id(profile)

    events: list[TimelineEvent] = []

    # --- Skeleton: connect + login (+ optional VPN) ---
    connect_time = login_time - timedelta(minutes=faker.random.randint(1, 4))
    events.append(
        event_factory.create(
            timestamp=connect_time,
            event_type=DEVICE_CONNECT,
            **common,
        )
    )
    events.append(
        event_factory.create(
            timestamp=login_time,
            event_type=LOGIN,
            **common,
        )
    )

    cursor = login_time + timedelta(minutes=faker.random.randint(1, 4))
    used_vpn = False
    if faker.random.random() < profile.vpn_usage_probability:
        events.append(
            event_factory.create(
                timestamp=cursor,
                event_type=VPN_CONNECT,
                resource_id=vpn_resource,
                **common,
            )
        )
        used_vpn = True
        cursor += timedelta(minutes=faker.random.randint(1, 3))

    # Target 20–40 total events for the workday.
    target_total = faker.random.randint(20, 40)
    # Keep enough work activities that totals land in the 20–40 band
    # after connect/login/VPN/lunch/logout skeleton events.
    remaining = max(16, target_total - 8)

    if lunch is not None:
        break_start, break_end = lunch
        morning_end = break_start
        afternoon_start = break_end + timedelta(minutes=1)
        morning_count = max(5, remaining // 2)
        afternoon_count = max(5, remaining - morning_count)
    else:
        break_start = break_end = None
        midpoint = login_time + (logout_time - login_time) / 2
        morning_end = midpoint
        afternoon_start = midpoint + timedelta(minutes=1)
        morning_count = max(5, remaining // 2)
        afternoon_count = max(5, remaining - morning_count)

    morning_times = _spread_timestamps(
        cursor,
        morning_end - timedelta(minutes=2),
        morning_count,
        faker,
    )
    for timestamp in morning_times:
        events.append(
            _emit_work_activity(
                event_factory=event_factory,
                timestamp=timestamp,
                profile=profile,
                employee=employee,
                work_pool=work_pool,
                meeting_resource=meeting_resource,
                email_resource=email_resource,
                common=common,
                faker=faker,
            )
        )

    if lunch is not None and break_start is not None and break_end is not None:
        events.append(
            event_factory.create(
                timestamp=break_start,
                event_type=BREAK_START,
                metadata={"break_type": "lunch"},
                **common,
            )
        )
        events.append(
            event_factory.create(
                timestamp=break_end,
                event_type=BREAK_END,
                metadata={"break_type": "lunch"},
                **common,
            )
        )

    afternoon_times = _spread_timestamps(
        afternoon_start,
        logout_time - timedelta(minutes=10),
        afternoon_count,
        faker,
    )
    for timestamp in afternoon_times:
        events.append(
            _emit_work_activity(
                event_factory=event_factory,
                timestamp=timestamp,
                profile=profile,
                employee=employee,
                work_pool=work_pool,
                meeting_resource=meeting_resource,
                email_resource=email_resource,
                common=common,
                faker=faker,
            )
        )

    # Optional VPN disconnect shortly before the single end-of-day logout.
    final_cursor = logout_time - timedelta(minutes=faker.random.randint(2, 6))
    if used_vpn:
        events.append(
            event_factory.create(
                timestamp=final_cursor,
                event_type=VPN_DISCONNECT,
                resource_id=vpn_resource,
                **common,
            )
        )

    events.append(
        event_factory.create(
            timestamp=logout_time,
            event_type=LOGOUT,
            **common,
        )
    )
    session.logout_time = logout_time

    events.sort(key=lambda event: (event.timestamp, event.event_id))

    # Safety: ensure exactly one LOGOUT and that lunch precedes it.
    logout_events = [event for event in events if event.event_type == LOGOUT]
    assert len(logout_events) == 1
    if lunch is not None:
        break_events = [event for event in events if event.event_type == BREAK_START]
        if break_events:
            assert break_events[0].timestamp < logout_events[0].timestamp

    return events, [session]


def generate_workday_timelines(
    employees: Sequence[Employee],
    profiles: Mapping[str, BehaviorProfile],
    devices: Sequence[Device],
    *,
    work_date: date | None = None,
    faker: Faker | None = None,
) -> list[TimelineEvent]:
    """Generate one normal workday timeline for every employee.

    Args:
        employees: Enterprise workforce.
        profiles: Mapping of ``employee_id -> BehaviorProfile``.
        devices: All enterprise devices (used to resolve trusted device details).
        work_date: Calendar day to simulate. Defaults to today.
        faker: Optional Faker instance for reproducible randomness.

    Returns:
        All generated timeline events sorted chronologically.
    """
    fake = faker or Faker()
    day = work_date or date.today()
    devices_by_id = {device.device_id: device for device in devices}

    event_factory = EventFactory()
    session_factory = SessionFactory()

    all_events: list[TimelineEvent] = []

    for employee in employees:
        profile = profiles.get(employee.employee_id)
        if profile is None:
            continue

        employee_events, _sessions = _generate_employee_workday(
            employee=employee,
            profile=profile,
            devices_by_id=devices_by_id,
            work_date=day,
            event_factory=event_factory,
            session_factory=session_factory,
            faker=fake,
        )
        all_events.extend(employee_events)

    all_events.sort(key=lambda event: (event.timestamp, event.event_id))
    return all_events


def generate_workday_timelines_with_sessions(
    employees: Sequence[Employee],
    profiles: Mapping[str, BehaviorProfile],
    devices: Sequence[Device],
    *,
    work_date: date | None = None,
    faker: Faker | None = None,
) -> tuple[list[TimelineEvent], list[Session]]:
    """Generate workday timelines and the underlying session objects.

    Same behaviour as ``generate_workday_timelines``, also returning sessions
    for callers that need session metadata.
    """
    fake = faker or Faker()
    day = work_date or date.today()
    devices_by_id = {device.device_id: device for device in devices}

    event_factory = EventFactory()
    session_factory = SessionFactory()

    all_events: list[TimelineEvent] = []
    all_sessions: list[Session] = []

    for employee in employees:
        profile = profiles.get(employee.employee_id)
        if profile is None:
            continue

        employee_events, sessions = _generate_employee_workday(
            employee=employee,
            profile=profile,
            devices_by_id=devices_by_id,
            work_date=day,
            event_factory=event_factory,
            session_factory=session_factory,
            faker=fake,
        )
        all_events.extend(employee_events)
        all_sessions.extend(sessions)

    all_events.sort(key=lambda event: (event.timestamp, event.event_id))
    return all_events, all_sessions
