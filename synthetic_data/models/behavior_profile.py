"""Behavior profile domain model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class BehaviorProfile:
    """Baseline behavioral expectations for an employee.

    This is a schema-only model. It does not generate, infer, or simulate
    behavior; consumers supply values when constructing an instance.

    Attributes:
        profile_id: Stable unique identifier for the behavior profile.
        employee_id: Identifier of the employee this profile describes.
        typical_login_start: Typical earliest login hour (0–23, local time).
        typical_login_end: Typical latest login hour (0–23, local time).
        working_days: Days of week the employee usually works
            (for example: ``["Mon", "Tue", "Wed", "Thu", "Fri"]``).
        preferred_locations: Location identifiers the employee commonly uses.
        trusted_devices: Device identifiers considered normal for the employee.
        usual_resources: Resource identifiers the employee typically accesses.
        average_session_duration: Typical session length in minutes.
        average_daily_logins: Typical number of logins per working day.
        vpn_usage_probability: Likelihood of VPN use on a given session (0.0–1.0).
        travel_probability: Likelihood of travel-related access patterns (0.0–1.0).
        remote_work_probability: Likelihood of remote work on a given day (0.0–1.0).
        preferred_login_days: Days the employee typically authenticates.
        normal_login_locations: Location identifiers considered normal at login.
        normal_login_hours_variance: Expected login-time drift in hours.
        average_resources_per_session: Typical distinct resources touched per session.
        average_failed_logins_per_month: Typical failed authentication attempts monthly.
        normal_browser_usage: Browsers commonly used by the employee.
        normal_operating_systems: Operating systems commonly used by the employee.
        device_switch_probability: Likelihood of switching devices within a day (0.0–1.0).
    """

    profile_id: str
    employee_id: str
    typical_login_start: int = 9
    typical_login_end: int = 18
    working_days: list[str] = field(
        default_factory=lambda: ["Mon", "Tue", "Wed", "Thu", "Fri"]
    )
    preferred_locations: list[str] = field(default_factory=list)
    trusted_devices: list[str] = field(default_factory=list)
    usual_resources: list[str] = field(default_factory=list)
    average_session_duration: float = 480.0
    average_daily_logins: float = 1.0
    vpn_usage_probability: float = 0.0
    travel_probability: float = 0.0
    remote_work_probability: float = 0.0
    preferred_login_days: list[str] = field(
        default_factory=lambda: ["Mon", "Tue", "Wed", "Thu", "Fri"]
    )
    normal_login_locations: list[str] = field(default_factory=list)
    normal_login_hours_variance: int = 1
    average_resources_per_session: float = 4.0
    average_failed_logins_per_month: float = 1.0
    normal_browser_usage: list[str] = field(default_factory=list)
    normal_operating_systems: list[str] = field(default_factory=list)
    device_switch_probability: float = 0.1
