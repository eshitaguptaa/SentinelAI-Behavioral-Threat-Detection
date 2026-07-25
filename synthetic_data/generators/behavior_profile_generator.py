"""Role-aware behavior profile generator.

Creates one ``BehaviorProfile`` per employee. This module defines expected
baselines only — it does not emit login events, sessions, or attacks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from faker import Faker

from synthetic_data.models import BehaviorProfile, Employee, Location, Resource

WEEKDAYS: Final[list[str]] = ["Mon", "Tue", "Wed", "Thu", "Fri"]
ALL_DAYS: Final[list[str]] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass(frozen=True, slots=True)
class RoleBehaviorTemplate:
    """Static behavioral expectations for a workforce role.

    Range fields are sampled uniformly per employee at generation time.
    """

    typical_login_start: int
    typical_login_end: int
    working_days: tuple[str, ...]
    preferred_resource_names: tuple[str, ...]
    average_session_duration: tuple[float, float]
    average_daily_logins: tuple[float, float]
    vpn_usage_probability: tuple[float, float]
    remote_work_probability: tuple[float, float]
    normal_login_hours_variance: int
    normal_browsers: tuple[str, ...]
    normal_operating_systems: tuple[str, ...]
    failed_logins_per_month: tuple[float, float]
    resources_per_session: tuple[float, float]
    device_switch_probability: tuple[float, float]
    travel_probability: tuple[float, float]
    rotating_shifts: bool = False


# Role → baseline template. Resource names are resolved against the enterprise
# catalog at generation time (unknown names are skipped).
ROLE_TEMPLATES: Final[dict[str, RoleBehaviorTemplate]] = {
    "Software Engineer": RoleBehaviorTemplate(
        typical_login_start=9,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("GitHub", "Jira", "Confluence", "Slack", "VPN"),
        average_session_duration=(360.0, 480.0),
        average_daily_logins=(1.5, 3.0),
        vpn_usage_probability=(0.30, 0.60),
        remote_work_probability=(0.30, 0.60),
        normal_login_hours_variance=1,
        normal_browsers=("Chrome", "Edge"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(4.0, 8.0),
        device_switch_probability=(0.05, 0.15),
        travel_probability=(0.02, 0.10),
    ),
    "Senior Engineer": RoleBehaviorTemplate(
        typical_login_start=9,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=(
            "GitHub",
            "GitLab",
            "Jira",
            "Confluence",
            "AWS Console",
            "VPN",
        ),
        average_session_duration=(400.0, 500.0),
        average_daily_logins=(2.0, 3.5),
        vpn_usage_probability=(0.40, 0.70),
        remote_work_probability=(0.30, 0.60),
        normal_login_hours_variance=1,
        normal_browsers=("Chrome", "Edge", "Firefox"),
        normal_operating_systems=("Windows", "macOS", "Linux"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(5.0, 9.0),
        device_switch_probability=(0.05, 0.18),
        travel_probability=(0.05, 0.15),
    ),
    "Security Analyst": RoleBehaviorTemplate(
        typical_login_start=6,
        typical_login_end=14,
        working_days=tuple(ALL_DAYS),
        preferred_resource_names=("SIEM", "VPN", "Logs", "AWS Console", "Azure Portal"),
        average_session_duration=(420.0, 540.0),
        average_daily_logins=(2.5, 4.5),
        vpn_usage_probability=(0.70, 0.95),
        remote_work_probability=(0.20, 0.50),
        normal_login_hours_variance=3,
        normal_browsers=("Chrome", "Firefox"),
        normal_operating_systems=("Windows", "Linux"),
        failed_logins_per_month=(0.0, 3.0),
        resources_per_session=(6.0, 10.0),
        device_switch_probability=(0.15, 0.30),
        travel_probability=(0.10, 0.30),
        rotating_shifts=True,
    ),
    "Finance Analyst": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=17,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("Payroll", "Finance Database", "Email", "Microsoft Teams"),
        average_session_duration=(330.0, 420.0),
        average_daily_logins=(1.0, 2.5),
        vpn_usage_probability=(0.10, 0.30),
        remote_work_probability=(0.10, 0.30),
        normal_login_hours_variance=1,
        normal_browsers=("Edge", "Chrome"),
        normal_operating_systems=("Windows",),
        failed_logins_per_month=(0.0, 1.0),
        resources_per_session=(3.0, 6.0),
        device_switch_probability=(0.02, 0.08),
        travel_probability=(0.00, 0.05),
    ),
    "HR Executive": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=17,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("HR Portal", "Payroll", "Email", "Microsoft Teams"),
        average_session_duration=(300.0, 390.0),
        average_daily_logins=(1.0, 2.5),
        vpn_usage_probability=(0.20, 0.40),
        remote_work_probability=(0.20, 0.40),
        normal_login_hours_variance=1,
        normal_browsers=("Edge", "Chrome"),
        normal_operating_systems=("Windows",),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(3.0, 5.0),
        device_switch_probability=(0.05, 0.15),
        travel_probability=(0.05, 0.15),
    ),
    "Sales Executive": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("CRM", "Email", "VPN", "Microsoft Teams"),
        average_session_duration=(240.0, 360.0),
        average_daily_logins=(2.0, 5.0),
        vpn_usage_probability=(0.40, 0.70),
        remote_work_probability=(0.50, 0.80),
        normal_login_hours_variance=2,
        normal_browsers=("Chrome", "Safari"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(1.0, 4.0),
        resources_per_session=(4.0, 7.0),
        device_switch_probability=(0.30, 0.60),
        travel_probability=(0.40, 0.80),
    ),
    "Marketing Executive": RoleBehaviorTemplate(
        typical_login_start=9,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("CRM", "Email", "Confluence", "Slack"),
        average_session_duration=(270.0, 390.0),
        average_daily_logins=(1.5, 3.5),
        vpn_usage_probability=(0.30, 0.60),
        remote_work_probability=(0.40, 0.70),
        normal_login_hours_variance=1,
        normal_browsers=("Chrome", "Safari"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(3.0, 6.0),
        device_switch_probability=(0.10, 0.25),
        travel_probability=(0.10, 0.30),
    ),
    "Legal Counsel": RoleBehaviorTemplate(
        typical_login_start=9,
        typical_login_end=17,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("Email", "Knowledge Base", "Finance Database", "Microsoft Teams"),
        average_session_duration=(300.0, 420.0),
        average_daily_logins=(1.0, 2.5),
        vpn_usage_probability=(0.20, 0.40),
        remote_work_probability=(0.10, 0.30),
        normal_login_hours_variance=1,
        normal_browsers=("Edge", "Chrome"),
        normal_operating_systems=("Windows",),
        failed_logins_per_month=(0.0, 1.0),
        resources_per_session=(3.0, 5.0),
        device_switch_probability=(0.05, 0.12),
        travel_probability=(0.05, 0.20),
    ),
    "Operations Engineer": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=17,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("Jira", "VPN", "AWS Console", "Azure Portal", "Slack"),
        average_session_duration=(360.0, 450.0),
        average_daily_logins=(1.5, 3.0),
        vpn_usage_probability=(0.35, 0.65),
        remote_work_probability=(0.20, 0.40),
        normal_login_hours_variance=2,
        normal_browsers=("Chrome", "Firefox"),
        normal_operating_systems=("Windows", "Linux"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(4.0, 8.0),
        device_switch_probability=(0.10, 0.25),
        travel_probability=(0.05, 0.15),
    ),
    "Intern": RoleBehaviorTemplate(
        typical_login_start=10,
        typical_login_end=17,
        working_days=tuple(WEEKDAYS),
        preferred_resource_names=("Email", "Knowledge Base", "Slack", "Confluence"),
        average_session_duration=(240.0, 360.0),
        average_daily_logins=(1.0, 2.5),
        vpn_usage_probability=(0.10, 0.30),
        remote_work_probability=(0.05, 0.25),
        normal_login_hours_variance=1,
        normal_browsers=("Chrome", "Edge"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(1.0, 3.0),
        resources_per_session=(2.0, 5.0),
        device_switch_probability=(0.05, 0.15),
        travel_probability=(0.00, 0.05),
    ),
    "Director": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        # Resources are resolved from the department catalog (+ director extras).
        preferred_resource_names=(),
        average_session_duration=(300.0, 420.0),
        average_daily_logins=(2.0, 4.0),
        vpn_usage_probability=(0.50, 0.80),
        remote_work_probability=(0.40, 0.70),
        normal_login_hours_variance=2,
        normal_browsers=("Chrome", "Edge"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(5.0, 8.0),
        device_switch_probability=(0.20, 0.50),
        travel_probability=(0.20, 0.50),
    ),
    "Manager": RoleBehaviorTemplate(
        typical_login_start=8,
        typical_login_end=18,
        working_days=tuple(WEEKDAYS),
        # Resources are resolved from the department catalog only.
        preferred_resource_names=(),
        average_session_duration=(330.0, 420.0),
        average_daily_logins=(2.0, 4.0),
        vpn_usage_probability=(0.40, 0.70),
        remote_work_probability=(0.30, 0.60),
        normal_login_hours_variance=2,
        normal_browsers=("Chrome", "Edge"),
        normal_operating_systems=("Windows", "macOS"),
        failed_logins_per_month=(0.0, 2.0),
        resources_per_session=(4.0, 7.0),
        device_switch_probability=(0.15, 0.35),
        travel_probability=(0.15, 0.40),
    ),
}

_DEFAULT_TEMPLATE: Final[RoleBehaviorTemplate] = RoleBehaviorTemplate(
    typical_login_start=9,
    typical_login_end=17,
    working_days=tuple(WEEKDAYS),
    preferred_resource_names=("Email", "Microsoft Teams", "Knowledge Base"),
    average_session_duration=(300.0, 420.0),
    average_daily_logins=(1.0, 2.5),
    vpn_usage_probability=(0.15, 0.35),
    remote_work_probability=(0.20, 0.40),
    normal_login_hours_variance=1,
    normal_browsers=("Chrome", "Edge"),
    normal_operating_systems=("Windows",),
    failed_logins_per_month=(0.0, 2.0),
    resources_per_session=(3.0, 6.0),
    device_switch_probability=(0.05, 0.15),
    travel_probability=(0.05, 0.15),
)

# Department-specific resources inherited by Managers (and Directors).
_DEPARTMENT_RESOURCES_FOR_LEADERSHIP: Final[dict[str, tuple[str, ...]]] = {
    "Engineering": ("GitHub", "GitLab", "Jira", "Confluence", "Slack", "VPN"),
    "Finance": ("Finance Database", "Payroll", "Email", "Microsoft Teams"),
    "Human Resources": ("HR Portal", "Payroll", "Email", "Microsoft Teams"),
    "Sales": ("CRM", "Email", "Microsoft Teams", "VPN"),
    "Marketing": ("CRM", "Confluence", "Slack", "Email"),
    "Legal": ("Knowledge Base", "Email", "Finance Database"),
    "Operations": ("AWS Console", "Azure Portal", "Jira", "VPN", "Slack"),
    # IT was not listed in the leadership catalog; keep a practical fallback.
    "IT": ("VPN", "AWS Console", "Azure Portal", "Jira", "Slack"),
}

# Directors also receive these enterprise-wide leadership resources.
_DIRECTOR_EXTRA_RESOURCES: Final[tuple[str, ...]] = (
    "Email",
    "Microsoft Teams",
    "Knowledge Base",
    "VPN",
)

_SECURITY_SHIFT_WINDOWS: Final[tuple[tuple[int, int], ...]] = (
    (6, 14),
    (14, 22),
    (22, 6),  # overnight wrap; end < start indicates overnight shift
)


def _clamp_probability(value: float) -> float:
    """Clamp a probability into the inclusive ``[0.0, 1.0]`` range."""
    return max(0.0, min(1.0, value))


def _sample_range(
    bounds: tuple[float, float],
    faker: Faker,
    *,
    precision: int = 2,
) -> float:
    """Sample a float uniformly from an inclusive ``[low, high]`` range."""
    low, high = bounds
    if high < low:
        low, high = high, low
    return round(faker.random.uniform(low, high), precision)


def _resolve_leadership_resources(
    role: str,
    department_name: str,
) -> tuple[str, ...]:
    """Resolve usual resources for Directors and Managers.

    Managers inherit only their department catalog.
    Directors inherit department resources plus leadership extras.
    """
    department_resources = _DEPARTMENT_RESOURCES_FOR_LEADERSHIP.get(department_name, ())

    if role == "Manager":
        return department_resources

    if role == "Director":
        return tuple(
            dict.fromkeys((*department_resources, *_DIRECTOR_EXTRA_RESOURCES))
        )

    return ()


def _resolve_template(
    employee: Employee,
    departments_by_id: Mapping[str, str],
) -> RoleBehaviorTemplate:
    """Select the role template for an employee."""
    template = ROLE_TEMPLATES.get(employee.role, _DEFAULT_TEMPLATE)

    if employee.role not in {"Director", "Manager"}:
        return template

    department_name = departments_by_id.get(employee.department_id, "")
    leadership_resources = _resolve_leadership_resources(
        employee.role,
        department_name,
    )
    return RoleBehaviorTemplate(
        typical_login_start=template.typical_login_start,
        typical_login_end=template.typical_login_end,
        working_days=template.working_days,
        preferred_resource_names=leadership_resources,
        average_session_duration=template.average_session_duration,
        average_daily_logins=template.average_daily_logins,
        vpn_usage_probability=template.vpn_usage_probability,
        remote_work_probability=template.remote_work_probability,
        normal_login_hours_variance=template.normal_login_hours_variance,
        normal_browsers=template.normal_browsers,
        normal_operating_systems=template.normal_operating_systems,
        failed_logins_per_month=template.failed_logins_per_month,
        resources_per_session=template.resources_per_session,
        device_switch_probability=template.device_switch_probability,
        travel_probability=template.travel_probability,
        rotating_shifts=template.rotating_shifts,
    )


def _resolve_resource_ids(
    preferred_names: Sequence[str],
    resources_by_name: Mapping[str, str],
) -> list[str]:
    """Map preferred resource display names to catalog resource IDs."""
    resolved: list[str] = []
    for name in preferred_names:
        resource_id = resources_by_name.get(name)
        if resource_id and resource_id not in resolved:
            resolved.append(resource_id)
    return resolved


def _preferred_locations(
    employee: Employee,
    location_ids: Sequence[str],
    faker: Faker,
) -> list[str]:
    """Build a small set of preferred location IDs for an employee."""
    preferred: list[str] = []
    if employee.office_location_id:
        preferred.append(employee.office_location_id)

    secondary_candidates = [
        location_id
        for location_id in location_ids
        if location_id not in preferred
    ]
    if secondary_candidates and faker.random.random() < 0.25:
        preferred.append(faker.random.choice(secondary_candidates))

    return preferred


def _login_window(
    template: RoleBehaviorTemplate,
    faker: Faker,
) -> tuple[int, int]:
    """Derive typical login start/end hours, including rotating shifts."""
    if not template.rotating_shifts:
        return template.typical_login_start, template.typical_login_end

    start, end = faker.random.choice(list(_SECURITY_SHIFT_WINDOWS))
    return start, end


def generate_behavior_profiles(
    employees: Sequence[Employee],
    resources: Sequence[Resource],
    *,
    locations: Sequence[Location] | None = None,
    departments_by_id: Mapping[str, str] | None = None,
    faker: Faker | None = None,
) -> dict[str, BehaviorProfile]:
    """Create one role-aware ``BehaviorProfile`` for every employee.

    Args:
        employees: Enterprise workforce to profile.
        resources: Enterprise resource catalog used to resolve usual resources.
        locations: Optional office locations for preferred-location selection.
        departments_by_id: Optional map of ``department_id -> department name``
            used to enrich Director/Manager resource preferences.
        faker: Optional Faker instance for reproducible variance.

    Returns:
        Mapping of ``employee_id`` to ``BehaviorProfile``.
    """
    fake = faker or Faker()
    resources_by_name = {
        resource.resource_name: resource.resource_id for resource in resources
    }
    location_ids = [location.location_id for location in (locations or [])]
    dept_names = dict(departments_by_id or {})

    profiles: dict[str, BehaviorProfile] = {}

    for index, employee in enumerate(employees, start=1):
        template = _resolve_template(employee, dept_names)
        login_start, login_end = _login_window(template, fake)
        preferred_locations = _preferred_locations(employee, location_ids, fake)
        working_days = list(template.working_days)

        profile = BehaviorProfile(
            profile_id=f"BPROF-{index:04d}",
            employee_id=employee.employee_id,
            typical_login_start=login_start,
            typical_login_end=login_end,
            working_days=working_days,
            preferred_locations=preferred_locations,
            trusted_devices=list(employee.assigned_device_ids),
            usual_resources=_resolve_resource_ids(
                template.preferred_resource_names,
                resources_by_name,
            ),
            average_session_duration=_sample_range(
                template.average_session_duration,
                fake,
                precision=1,
            ),
            average_daily_logins=_sample_range(
                template.average_daily_logins,
                fake,
                precision=1,
            ),
            vpn_usage_probability=_clamp_probability(
                _sample_range(template.vpn_usage_probability, fake)
            ),
            travel_probability=_clamp_probability(
                _sample_range(template.travel_probability, fake)
            ),
            remote_work_probability=_clamp_probability(
                _sample_range(template.remote_work_probability, fake)
            ),
            preferred_login_days=list(working_days),
            normal_login_locations=list(preferred_locations),
            normal_login_hours_variance=template.normal_login_hours_variance,
            average_resources_per_session=_sample_range(
                template.resources_per_session,
                fake,
                precision=1,
            ),
            average_failed_logins_per_month=_sample_range(
                template.failed_logins_per_month,
                fake,
                precision=1,
            ),
            normal_browser_usage=list(template.normal_browsers),
            normal_operating_systems=list(template.normal_operating_systems),
            device_switch_probability=_clamp_probability(
                _sample_range(template.device_switch_probability, fake)
            ),
        )
        profiles[employee.employee_id] = profile

    return profiles
