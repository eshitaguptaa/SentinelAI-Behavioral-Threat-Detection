"""Multi-day enterprise timeline simulation built on the daily timeline generator.

This module does not alter daily timeline generation. It orchestrates repeated
calls to ``generate_workday_timelines`` across a date range, applying leave,
remote, travel, and weekend rules from each BehaviourProfile.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, timedelta
from pathlib import Path
from typing import Final, Literal

from faker import Faker

from synthetic_data.config import NUMBER_OF_SIMULATION_DAYS, RANDOM_SEED
from synthetic_data.generators.dataset_exporter import export_simulation_datasets
from synthetic_data.generators.event_factory import TimelineEvent
from synthetic_data.generators.timeline_generator import generate_workday_timelines
from synthetic_data.models import BehaviorProfile, Device, Employee, Location

DAY_NAME_BY_WEEKDAY: Final[tuple[str, ...]] = (
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat",
    "Sun",
)

WorkMode = Literal["office", "remote", "travel", "leave", "off"]

REMOTE_LOCATION_ID: Final[str] = "LOC-REMOTE"
DEFAULT_LEAVE_PROBABILITY: Final[float] = 0.04


@dataclass(slots=True)
class SimulationResult:
    """Outcome of a multi-day enterprise timeline simulation."""

    events: list[TimelineEvent]
    employees: list[Employee]
    profiles: dict[str, BehaviorProfile]
    number_of_employees: int
    number_of_simulated_days: int
    number_of_events: int
    number_of_leave_days: int
    number_of_remote_work_days: int
    number_of_travel_days: int
    export_paths: dict[str, Path]


def _scheduled_day_names(profile: BehaviorProfile) -> set[str]:
    """Return the weekday names an employee is expected to work."""
    names = profile.preferred_login_days or profile.working_days or [
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
    ]
    return {name.strip() for name in names}


def _is_scheduled_workday(profile: BehaviorProfile, day: date) -> bool:
    """True when the profile indicates the employee works on ``day``."""
    day_name = DAY_NAME_BY_WEEKDAY[day.weekday()]
    return day_name in _scheduled_day_names(profile)


def _pick_travel_location(
    profile: BehaviorProfile,
    employee: Employee,
    locations: Sequence[Location],
    faker: Faker,
) -> str:
    """Choose a non-home office location for a legitimate travel day."""
    home_ids = {
        employee.office_location_id,
        *(profile.preferred_locations or []),
        *(profile.normal_login_locations or []),
    }
    home_ids.discard(None)
    candidates = [
        location.location_id
        for location in locations
        if location.location_id not in home_ids
    ]
    if not candidates:
        candidates = [location.location_id for location in locations]
    if not candidates:
        return "LOC-TRAVEL"
    return faker.random.choice(candidates)


def _day_profile_for_mode(
    profile: BehaviorProfile,
    *,
    mode: WorkMode,
    travel_location_id: str | None,
) -> BehaviorProfile:
    """Return a per-day profile view without mutating the stable baseline."""
    if mode == "remote":
        return replace(
            profile,
            preferred_locations=[REMOTE_LOCATION_ID],
            normal_login_locations=[REMOTE_LOCATION_ID],
            # Remote days typically rely more on VPN.
            vpn_usage_probability=min(1.0, max(profile.vpn_usage_probability, 0.75)),
        )
    if mode == "travel" and travel_location_id:
        return replace(
            profile,
            preferred_locations=[travel_location_id],
            normal_login_locations=[travel_location_id],
            vpn_usage_probability=min(1.0, max(profile.vpn_usage_probability, 0.55)),
        )
    return profile


def _choose_work_mode(
    profile: BehaviorProfile,
    faker: Faker,
    *,
    leave_probability: float,
) -> WorkMode:
    """Select leave / travel / remote / office for one employee-day."""
    if faker.random.random() < leave_probability:
        return "leave"
    # Mutually exclusive day modes; travel checked before remote.
    if faker.random.random() < profile.travel_probability:
        return "travel"
    if faker.random.random() < profile.remote_work_probability:
        return "remote"
    return "office"


def _renumber_events(
    events: Sequence[TimelineEvent],
    *,
    start_index: int,
) -> tuple[list[TimelineEvent], int]:
    """Assign globally unique event/session IDs across the multi-day run."""
    renumbered: list[TimelineEvent] = []
    session_map: dict[str, str] = {}
    next_event = start_index
    next_session = start_index

    for event in events:
        if event.session_id not in session_map:
            session_map[event.session_id] = f"SESS-{next_session:08d}"
            next_session += 1

        renumbered.append(
            TimelineEvent(
                event_id=f"EVT-{next_event:08d}",
                employee_id=event.employee_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                device_id=event.device_id,
                location_id=event.location_id,
                session_id=session_map[event.session_id],
                resource_id=event.resource_id,
                browser=event.browser,
                operating_system=event.operating_system,
                result=event.result,
                metadata=dict(event.metadata or {}),
            )
        )
        next_event += 1

    return renumbered, next_event


def simulate_enterprise_timeline(
    employees: Sequence[Employee],
    profiles: Mapping[str, BehaviorProfile],
    devices: Sequence[Device],
    locations: Sequence[Location],
    *,
    number_of_days: int | None = None,
    start_date: date | None = None,
    leave_probability: float = DEFAULT_LEAVE_PROBABILITY,
    output_dir: str | Path | None = None,
    export_csv: bool = True,
    seed: int | None = RANDOM_SEED,
    faker: Faker | None = None,
) -> SimulationResult:
    """Simulate normal enterprise activity across multiple days.

    Args:
        employees: Stable workforce identities for the full simulation.
        profiles: Stable BehaviourProfiles keyed by employee_id.
        devices: Enterprise devices (IDs remain stable across days).
        locations: Office locations used for travel-day selection.
        number_of_days: Calendar span to simulate (default from config / 30).
        start_date: First simulation day (defaults to today).
        leave_probability: Chance an otherwise scheduled day becomes leave.
        output_dir: Destination for CSV exports (defaults to ``datasets/``).
        export_csv: When True, write events/employees/behaviour_profiles CSVs.
        seed: Optional RNG seed for reproducibility.
        faker: Optional shared Faker instance.

    Returns:
        ``SimulationResult`` with events, counters, and export paths.
    """
    if number_of_days is None:
        number_of_days = NUMBER_OF_SIMULATION_DAYS
    if number_of_days <= 0:
        raise ValueError("number_of_days must be a positive integer")

    if seed is not None:
        Faker.seed(seed)
    fake = faker or Faker()
    if seed is not None:
        fake.seed_instance(seed)

    day_zero = start_date or date.today()
    stable_profiles = dict(profiles)
    employee_list = list(employees)

    all_events: list[TimelineEvent] = []
    leave_days = 0
    remote_days = 0
    travel_days = 0
    next_event_index = 1

    for offset in range(number_of_days):
        current_day = day_zero + timedelta(days=offset)
        active_employees: list[Employee] = []
        day_profiles: dict[str, BehaviorProfile] = {}
        modes: dict[str, WorkMode] = {}

        for employee in employee_list:
            profile = stable_profiles.get(employee.employee_id)
            if profile is None:
                continue

            if not _is_scheduled_workday(profile, current_day):
                continue

            mode = _choose_work_mode(
                profile,
                fake,
                leave_probability=leave_probability,
            )
            if mode == "leave":
                leave_days += 1
                continue

            travel_location_id = None
            if mode == "travel":
                travel_location_id = _pick_travel_location(
                    profile,
                    employee,
                    locations,
                    fake,
                )
                travel_days += 1
            elif mode == "remote":
                remote_days += 1

            day_profiles[employee.employee_id] = _day_profile_for_mode(
                profile,
                mode=mode,
                travel_location_id=travel_location_id,
            )
            modes[employee.employee_id] = mode
            active_employees.append(employee)

        if not active_employees:
            continue

        # Existing daily generator provides login/logout/break/event variation.
        day_events = generate_workday_timelines(
            active_employees,
            day_profiles,
            devices,
            work_date=current_day,
            faker=fake,
        )

        annotated: list[TimelineEvent] = []
        for event in day_events:
            metadata = dict(event.metadata or {})
            metadata["work_mode"] = modes.get(event.employee_id, "office")
            metadata["simulation_date"] = current_day.isoformat()
            annotated.append(
                TimelineEvent(
                    event_id=event.event_id,
                    employee_id=event.employee_id,
                    timestamp=event.timestamp,
                    event_type=event.event_type,
                    device_id=event.device_id,
                    location_id=event.location_id,
                    session_id=event.session_id,
                    resource_id=event.resource_id,
                    browser=event.browser,
                    operating_system=event.operating_system,
                    result=event.result,
                    metadata=metadata,
                )
            )

        renumbered, next_event_index = _renumber_events(
            annotated,
            start_index=next_event_index,
        )
        all_events.extend(renumbered)

    all_events.sort(key=lambda event: (event.timestamp, event.event_id))

    export_paths: dict[str, Path] = {}
    if export_csv:
        destination = Path(output_dir) if output_dir is not None else Path("datasets")
        export_paths = export_simulation_datasets(
            employees=employee_list,
            profiles=stable_profiles,
            events=all_events,
            output_dir=destination,
        )

    return SimulationResult(
        events=all_events,
        employees=employee_list,
        profiles=stable_profiles,
        number_of_employees=len(employee_list),
        number_of_simulated_days=number_of_days,
        number_of_events=len(all_events),
        number_of_leave_days=leave_days,
        number_of_remote_work_days=remote_days,
        number_of_travel_days=travel_days,
        export_paths=export_paths,
    )
