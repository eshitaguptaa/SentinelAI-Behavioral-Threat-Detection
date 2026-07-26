"""CSV export helpers for multi-day enterprise simulations."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from synthetic_data.generators.event_factory import TimelineEvent
from synthetic_data.models import BehaviorProfile, Employee


def _join_list(values: Sequence[object] | None) -> str:
    """Serialize a list field for CSV storage."""
    if not values:
        return ""
    return "|".join(str(value) for value in values)


def _metadata_json(metadata: Mapping[str, Any] | None) -> str:
    """Serialize full event metadata for round-trip (attack GT included)."""
    if not metadata:
        return ""
    return json.dumps(dict(metadata), default=str, separators=(",", ":"))


def export_employees_csv(employees: Sequence[Employee], path: Path) -> Path:
    """Write employee identity rows to ``employees.csv``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "employee_id",
        "full_name",
        "email",
        "department_id",
        "role",
        "manager_id",
        "office_location_id",
        "timezone",
        "work_start_hour",
        "work_end_hour",
        "assigned_device_ids",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for employee in employees:
            writer.writerow(
                {
                    "employee_id": employee.employee_id,
                    "full_name": employee.full_name,
                    "email": employee.email,
                    "department_id": employee.department_id,
                    "role": employee.role,
                    "manager_id": employee.manager_id or "",
                    "office_location_id": employee.office_location_id or "",
                    "timezone": employee.timezone,
                    "work_start_hour": employee.work_start_hour,
                    "work_end_hour": employee.work_end_hour,
                    "assigned_device_ids": _join_list(employee.assigned_device_ids),
                }
            )
    return path


def export_behaviour_profiles_csv(
    profiles: Mapping[str, BehaviorProfile],
    path: Path,
) -> Path:
    """Write behaviour profile rows to ``behaviour_profiles.csv``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "profile_id",
        "employee_id",
        "typical_login_start",
        "typical_login_end",
        "working_days",
        "preferred_locations",
        "trusted_devices",
        "usual_resources",
        "average_session_duration",
        "average_daily_logins",
        "vpn_usage_probability",
        "travel_probability",
        "remote_work_probability",
        "preferred_login_days",
        "normal_login_locations",
        "normal_login_hours_variance",
        "average_resources_per_session",
        "average_failed_logins_per_month",
        "normal_browser_usage",
        "normal_operating_systems",
        "device_switch_probability",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for profile in profiles.values():
            writer.writerow(
                {
                    "profile_id": profile.profile_id,
                    "employee_id": profile.employee_id,
                    "typical_login_start": profile.typical_login_start,
                    "typical_login_end": profile.typical_login_end,
                    "working_days": _join_list(profile.working_days),
                    "preferred_locations": _join_list(profile.preferred_locations),
                    "trusted_devices": _join_list(profile.trusted_devices),
                    "usual_resources": _join_list(profile.usual_resources),
                    "average_session_duration": profile.average_session_duration,
                    "average_daily_logins": profile.average_daily_logins,
                    "vpn_usage_probability": profile.vpn_usage_probability,
                    "travel_probability": profile.travel_probability,
                    "remote_work_probability": profile.remote_work_probability,
                    "preferred_login_days": _join_list(profile.preferred_login_days),
                    "normal_login_locations": _join_list(profile.normal_login_locations),
                    "normal_login_hours_variance": profile.normal_login_hours_variance,
                    "average_resources_per_session": profile.average_resources_per_session,
                    "average_failed_logins_per_month": profile.average_failed_logins_per_month,
                    "normal_browser_usage": _join_list(profile.normal_browser_usage),
                    "normal_operating_systems": _join_list(profile.normal_operating_systems),
                    "device_switch_probability": profile.device_switch_probability,
                }
            )
    return path


def export_events_csv(events: Iterable[TimelineEvent], path: Path) -> Path:
    """Write timeline events to ``events.csv``.

    Always writes ``work_mode`` / ``simulation_date`` for backward compatibility
    and ``metadata_json`` so attack ground-truth fields survive round-trips.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "event_id",
        "employee_id",
        "timestamp",
        "event_type",
        "device_id",
        "location_id",
        "session_id",
        "resource_id",
        "browser",
        "operating_system",
        "result",
        "work_mode",
        "simulation_date",
        "metadata_json",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            metadata = event.metadata or {}
            writer.writerow(
                {
                    "event_id": event.event_id,
                    "employee_id": event.employee_id,
                    "timestamp": event.timestamp.isoformat(sep=" "),
                    "event_type": event.event_type,
                    "device_id": event.device_id,
                    "location_id": event.location_id,
                    "session_id": event.session_id,
                    "resource_id": event.resource_id or "",
                    "browser": event.browser or "",
                    "operating_system": event.operating_system or "",
                    "result": event.result,
                    "work_mode": metadata.get("work_mode", "office"),
                    "simulation_date": metadata.get("simulation_date", ""),
                    "metadata_json": _metadata_json(metadata),
                }
            )
    return path


def export_simulation_datasets(
    *,
    employees: Sequence[Employee],
    profiles: Mapping[str, BehaviorProfile],
    events: Sequence[TimelineEvent],
    output_dir: Path,
) -> dict[str, Path]:
    """Export the standard SentinelAI simulation CSV bundle."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return {
        "employees": export_employees_csv(employees, output_dir / "employees.csv"),
        "behaviour_profiles": export_behaviour_profiles_csv(
            profiles,
            output_dir / "behaviour_profiles.csv",
        ),
        "events": export_events_csv(events, output_dir / "events.csv"),
    }
