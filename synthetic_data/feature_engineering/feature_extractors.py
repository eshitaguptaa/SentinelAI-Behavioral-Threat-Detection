"""Modular feature extractors for employee-day timeline aggregates.

Each extractor receives the (already grouped and time-sorted) events for one
employee on one simulation day and returns a flat feature dictionary. Extractors
are intentionally independent so they can be composed, tested, or extended
without changing the aggregation layer.

Events are structurally typed (``TimelineEventLike``) so this module does not
import ``synthetic_data.generators`` (avoids optional deps such as Faker).
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Event protocol + local event-type constants
# ---------------------------------------------------------------------------


@runtime_checkable
class TimelineEventLike(Protocol):
    """Minimal event shape required by extractors (matches ``TimelineEvent``)."""

    event_id: str
    employee_id: str
    timestamp: datetime
    event_type: str
    device_id: str
    location_id: str
    session_id: str
    resource_id: str | None
    browser: str | None
    operating_system: str | None
    result: str
    metadata: dict[str, Any]


# Mirrors synthetic_data.generators.event_catalog constants (kept local).
DEVICE_CONNECT = "DEVICE_CONNECT"
LOGIN = "LOGIN"
VPN_CONNECT = "VPN_CONNECT"
VPN_DISCONNECT = "VPN_DISCONNECT"
APPLICATION_ACCESS = "APPLICATION_ACCESS"
RESOURCE_ACCESS = "RESOURCE_ACCESS"
EMAIL_ACCESS = "EMAIL_ACCESS"
MEETING_JOIN = "MEETING_JOIN"
FILE_ACCESS = "FILE_ACCESS"
FILE_READ = "FILE_READ"
FILE_WRITE = "FILE_WRITE"
FILE_DOWNLOAD = "FILE_DOWNLOAD"
BREAK_START = "BREAK_START"
LOGOUT = "LOGOUT"
FAILED_LOGIN = "FAILED_LOGIN"
ADMIN_LOGIN = "ADMIN_LOGIN"
SSH_LOGIN = "SSH_LOGIN"
USB_INSERT = "USB_INSERT"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_RESOURCE_TOKENS: frozenset[str] = frozenset(
    {
        "PAYROLL",
        "FINANCE",
        "HR_",
        "SOURCE_CODE",
        "ADMIN",
        "SECRET",
        "CREDENTIAL",
        "DATABASE",
        "AWS",
        "KEYVAULT",
        "PRIVILEGE",
    }
)

_ATTACK_TYPE_KEYS: tuple[tuple[str, str], ...] = (
    ("IMPOSSIBLE_TRAVEL", "impossible_travel_count"),
    ("CREDENTIAL_THEFT", "credential_theft_count"),
    ("PRIVILEGE_ESCALATION", "privilege_escalation_count"),
    ("DATA_EXFILTRATION", "data_exfiltration_count"),
    ("AFTER_HOURS_ACCESS", "after_hours_attack_count"),
    ("LATERAL_MOVEMENT", "lateral_movement_count"),
    ("BRUTE_FORCE_LOGIN", "brute_force_count"),
)

_AUTH_EVENT_TYPES: frozenset[str] = frozenset(
    {
        LOGIN,
        LOGOUT,
        FAILED_LOGIN,
        ADMIN_LOGIN,
        VPN_CONNECT,
        VPN_DISCONNECT,
        "PASSWORD_CHANGE",
        "MFA_SUCCESS",
        "MFA_FAILURE",
    }
)
_RESOURCE_TOUCH_TYPES: frozenset[str] = frozenset(
    {
        APPLICATION_ACCESS,
        RESOURCE_ACCESS,
        FILE_ACCESS,
        FILE_READ,
        FILE_WRITE,
        FILE_DOWNLOAD,
        "FILE_DELETE",
        "FILE_UPLOAD",
        EMAIL_ACCESS,
        "SLACK_ACCESS",
        "TEAMS_ACCESS",
        MEETING_JOIN,
        "GITHUB_ACCESS",
        "GIT_PULL",
        "GIT_PUSH",
        "JIRA_ACCESS",
        "DOCKER_ACCESS",
        "AWS_CONSOLE",
        "AZURE_PORTAL",
        "DATABASE_ACCESS",
        SSH_LOGIN,
        "REMOTE_DESKTOP",
        "API_REQUEST",
        "CRM_ACCESS",
        "ANALYTICS_ACCESS",
        "CANVA_ACCESS",
        "PAYROLL_ACCESS",
        "EXCEL_ACCESS",
        "HR_RECORDS_ACCESS",
        "DOCUMENT_ACCESS",
        ADMIN_LOGIN,
        "PRIVILEGE_ESCALATION",
        "POLICY_CHANGE",
    }
)
_FAILURE_RESULTS: frozenset[str] = frozenset(
    {"failure", "fail", "failed", "denied", "error"}
)
_SUCCESS_RESULTS: frozenset[str] = frozenset({"success", "ok", "allowed"})

# Stable location → country map (mirrors attack modules; no external deps).
_LOCATION_TO_COUNTRY: dict[str, str] = {
    "LOC-BENGALURU": "India",
    "LOC-HYDERABAD": "India",
    "LOC-LONDON": "United Kingdom",
    "LOC-NEW_YORK": "United States",
    "LOC-SINGAPORE": "Singapore",
    "LOC-REMOTE": "Remote",
    "LOC-TRAVEL": "Travel",
    "LOC-BERLIN": "Germany",
    "LOC-SYDNEY": "Australia",
    "LOC-TOKYO": "Japan",
    "LOC-TORONTO": "Canada",
}

FeatureDict = dict[str, int | float]


class FeatureExtractor(Protocol):
    """Protocol for employee-day feature extractors."""

    name: str

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        """Extract a feature dictionary from one employee-day event group."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _meta(event: TimelineEventLike) -> Mapping[str, Any]:
    """Return event metadata mapping (never None)."""
    return event.metadata or {}


def _is_attack_event(event: TimelineEventLike) -> bool:
    """True when metadata marks the event as attack-injected."""
    meta = _meta(event)
    return bool(meta.get("is_attack")) or bool(meta.get("attack_type"))


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Coerce a metadata value to float, falling back to ``default``."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _population_std(values: Sequence[float]) -> float:
    """Population standard deviation (deterministic, no numpy)."""
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    if n == 1:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(var)


def _shannon_entropy(counts: Mapping[str, int]) -> float:
    """Shannon entropy in bits over a categorical count map."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _is_sensitive_resource(resource_id: str | None) -> bool:
    """Heuristic: resource id contains a sensitive token."""
    if not resource_id:
        return False
    upper = resource_id.upper()
    return any(token in upper for token in _SENSITIVE_RESOURCE_TOKENS)


def _hour_fraction(ts: datetime) -> float:
    """Hour of day as a float including minutes/seconds."""
    return ts.hour + ts.minute / 60.0 + ts.second / 3600.0


def _is_after_hours(ts: datetime) -> bool:
    """Business-hours heuristic: outside 08:00–18:00 local event time."""
    return ts.hour < 8 or ts.hour >= 18


def _is_night(ts: datetime) -> bool:
    """Night window: 00:00–05:59."""
    return ts.hour < 6


def _median(values: Sequence[float]) -> float:
    """Median of a numeric sequence (O(k log k) sort; k is typically tiny)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _resolve_country(event: TimelineEventLike) -> str | None:
    """Resolve a country label from metadata or location_id.

    Preference order:
    1. Explicit metadata country fields
    2. Known ``LOC-*`` → country map
    3. ``LOC-`` suffix token as a stable proxy (e.g. ``LOC-PARIS`` → ``PARIS``)
    """
    meta = _meta(event)
    for key in (
        "country",
        "destination_country",
        "origin_country",
        "attacker_country",
    ):
        raw = meta.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()

    loc = (event.location_id or "").strip()
    if not loc:
        return None
    mapped = _LOCATION_TO_COUNTRY.get(loc)
    if mapped is not None:
        return mapped
    upper = loc.upper()
    if upper.startswith("LOC-") and len(upper) > 4:
        return upper[4:]
    return loc


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


class IdentityExtractor:
    """Endpoint / identity diversity features including device entropy."""

    name = "identity"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        devices: set[str] = set()
        locations: set[str] = set()
        browsers: set[str] = set()
        systems: set[str] = set()
        device_counts: Counter[str] = Counter()

        for event in events:
            if event.device_id:
                devices.add(event.device_id)
                device_counts[event.device_id] += 1
            if event.location_id:
                locations.add(event.location_id)
            if event.browser:
                browsers.add(event.browser)
            if event.operating_system:
                systems.add(event.operating_system)

        return {
            "unique_device_count": len(devices),
            "unique_location_count": len(locations),
            "unique_browser_count": len(browsers),
            "unique_os_count": len(systems),
            "device_entropy": _shannon_entropy(device_counts),
        }


class BehaviourExtractor:
    """Core activity / event-type behaviour counts."""

    name = "behaviour"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        type_counts: Counter[str] = Counter()
        for event in events:
            type_counts[event.event_type] += 1

        return {
            "total_events": len(events),
            "login_count": type_counts[LOGIN],
            "logout_count": type_counts[LOGOUT],
            "application_access_count": type_counts[APPLICATION_ACCESS],
            "resource_access_count": type_counts[RESOURCE_ACCESS],
            "email_access_count": type_counts[EMAIL_ACCESS],
            "meeting_join_count": type_counts[MEETING_JOIN],
            "break_start_count": type_counts[BREAK_START],
            "device_connect_count": type_counts[DEVICE_CONNECT],
            "unique_event_type_count": len(type_counts),
        }


class ResourceExtractor:
    """Resource access patterns, sensitive-target heuristics, and entropy."""

    name = "resource"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        resources: set[str] = set()
        resource_counts: Counter[str] = Counter()
        touch = 0
        sensitive = 0
        switches = 0
        previous: str | None = None

        for event in events:
            rid = event.resource_id
            if rid is None:
                continue
            resources.add(rid)
            resource_counts[rid] += 1
            if event.event_type in _RESOURCE_TOUCH_TYPES:
                touch += 1
            if _is_sensitive_resource(rid):
                sensitive += 1
            if previous is not None and rid != previous:
                switches += 1
            previous = rid

        return {
            "unique_resource_count": len(resources),
            "resource_touch_count": touch,
            "sensitive_resource_count": sensitive,
            "resource_switch_count": switches,
            "resource_entropy": _shannon_entropy(resource_counts),
        }


class AuthenticationExtractor:
    """Login / VPN / auth outcome features including failed-login streaks."""

    name = "authentication"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        success = 0
        failure = 0
        vpn_in = 0
        vpn_out = 0
        logins = 0
        logouts = 0
        fail_streak = 0
        max_fail_streak = 0

        for event in events:
            result = (event.result or "").lower()
            if event.event_type in _AUTH_EVENT_TYPES:
                if result in _SUCCESS_RESULTS:
                    success += 1
                elif result in _FAILURE_RESULTS:
                    failure += 1

            if event.event_type == VPN_CONNECT:
                vpn_in += 1
            elif event.event_type == VPN_DISCONNECT:
                vpn_out += 1
            elif event.event_type == LOGIN:
                logins += 1
                # Streak uses LOGIN events only (time-ordered input assumed).
                if result in _FAILURE_RESULTS:
                    fail_streak += 1
                    if fail_streak > max_fail_streak:
                        max_fail_streak = fail_streak
                else:
                    fail_streak = 0
            elif event.event_type == LOGOUT:
                logouts += 1

        auth_total = success + failure
        failure_rate = (failure / auth_total) if auth_total else 0.0

        return {
            "auth_success_count": success,
            "auth_failure_count": failure,
            "auth_failure_rate": failure_rate,
            "max_failed_login_streak": max_fail_streak,
            "vpn_connect_count": vpn_in,
            "vpn_disconnect_count": vpn_out,
            "login_logout_delta": logins - logouts,
        }


class NetworkExtractor:
    """Location / country / VPN / network identity features."""

    name = "network"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        location_changes = 0
        country_changes = 0
        remote = 0
        source_ips: set[str] = set()
        prev_location: str | None = None
        prev_country: str | None = None
        session_locations: dict[str, set[str]] = defaultdict(set)
        vpn_events = 0

        for event in events:
            loc = event.location_id or ""
            if prev_location is not None and loc and loc != prev_location:
                location_changes += 1
            if loc:
                prev_location = loc

            country = _resolve_country(event)
            if (
                prev_country is not None
                and country is not None
                and country != prev_country
            ):
                country_changes += 1
            if country is not None:
                prev_country = country

            if loc == "LOC-REMOTE" or "REMOTE" in loc.upper():
                remote += 1

            meta = _meta(event)
            ip = meta.get("source_ip")
            if isinstance(ip, str) and ip:
                source_ips.add(ip)

            if event.session_id and loc:
                session_locations[event.session_id].add(loc)

            if event.event_type in {VPN_CONNECT, VPN_DISCONNECT}:
                vpn_events += 1

        cross_location_sessions = sum(
            1 for locs in session_locations.values() if len(locs) > 1
        )
        total = len(events)
        vpn_ratio = (vpn_events / total) if total else 0.0

        return {
            "location_change_count": location_changes,
            "country_change_count": country_changes,
            "remote_event_count": remote,
            "unique_source_ip_count": len(source_ips),
            "cross_location_session_count": cross_location_sessions,
            "vpn_usage_ratio": vpn_ratio,
        }


class FileActivityExtractor:
    """File access and download-volume features."""

    name = "file_activity"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        file_access = 0
        size_sum = 0.0
        size_max = 0.0
        mass = 0
        total = len(events)

        for event in events:
            meta = _meta(event)
            size = _safe_float(meta.get("download_size_mb"))
            if size > 0:
                size_sum += size
                if size > size_max:
                    size_max = size
            if size >= 50.0:
                mass += 1

            stage = str(meta.get("attack_stage_label") or "")
            if "Mass Download" in stage or "mass_download" in stage.lower():
                mass += 1

            if event.event_type == FILE_ACCESS or event.event_type in {
                FILE_READ,
                FILE_WRITE,
                FILE_DOWNLOAD,
                "FILE_DELETE",
                "FILE_UPLOAD",
            }:
                file_access += 1

        ratio = (file_access / total) if total else 0.0
        return {
            "file_access_count": file_access,
            "download_size_mb_sum": size_sum,
            "download_size_mb_max": size_max,
            "mass_download_event_count": mass,
            "file_access_ratio": ratio,
        }


class AttackExtractor:
    """Attack-injection ground-truth features from event metadata.

    These fields are retained for evaluation, confusion matrices, dashboards,
    and explainability. They are excluded from ``FeatureVector.ml_features()``
    so Isolation Forest cannot train on labels.
    """

    name = "attack"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        attack_count = 0
        attack_types: set[str] = set()
        type_counts: Counter[str] = Counter()
        max_confidence = 0.0

        for event in events:
            meta = _meta(event)
            if not _is_attack_event(event):
                continue
            attack_count += 1
            attack_type = str(meta.get("attack_type") or "")
            if attack_type:
                attack_types.add(attack_type)
                type_counts[attack_type] += 1

            confidence = _safe_float(meta.get("attack_confidence"))
            if confidence > max_confidence:
                max_confidence = confidence

        total = len(events)
        features: FeatureDict = {
            "attack_event_count": attack_count,
            "attack_event_ratio": (attack_count / total) if total else 0.0,
            "unique_attack_type_count": len(attack_types),
            "has_attack": 1 if attack_count > 0 else 0,
            "max_attack_confidence": max_confidence,
        }
        for attack_type, field_name in _ATTACK_TYPE_KEYS:
            features[field_name] = type_counts[attack_type]
        return features


class TemporalExtractor:
    """Time-of-day, login-hour distribution, and calendar temporal features."""

    name = "temporal"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        empty = {
            "first_event_hour": 0.0,
            "last_event_hour": 0.0,
            "mean_login_hour": 0.0,
            "median_login_hour": 0.0,
            "std_login_hour": 0.0,
            "active_duration_hours": 0.0,
            "after_hours_event_count": 0,
            "night_event_count": 0,
            "is_weekend": 0,
            "weekday": 0,
            "unique_active_hour_count": 0,
        }
        if not events:
            return empty

        first = events[0].timestamp
        last = events[-1].timestamp
        after_hours = 0
        night = 0
        hours: set[int] = set()
        login_hours: list[float] = []

        for event in events:
            ts = event.timestamp
            hours.add(ts.hour)
            if _is_after_hours(ts):
                after_hours += 1
            if _is_night(ts):
                night += 1
            if event.event_type == LOGIN:
                login_hours.append(_hour_fraction(ts))

        if login_hours:
            mean_login = sum(login_hours) / len(login_hours)
            median_login = _median(login_hours)
            std_login = _population_std(login_hours)
        else:
            mean_login = 0.0
            median_login = 0.0
            std_login = 0.0

        duration_sec = max(0.0, (last - first).total_seconds())
        return {
            "first_event_hour": _hour_fraction(first),
            "last_event_hour": _hour_fraction(last),
            "mean_login_hour": mean_login,
            "median_login_hour": median_login,
            "std_login_hour": std_login,
            "active_duration_hours": duration_sec / 3600.0,
            "after_hours_event_count": after_hours,
            "night_event_count": night,
            "is_weekend": 1 if first.weekday() >= 5 else 0,
            "weekday": first.weekday(),
            "unique_active_hour_count": len(hours),
        }


class StatisticsExtractor:
    """Distributional / entropy / idle-gap / burstiness features."""

    name = "statistics"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        if not events:
            return {
                "events_per_hour_mean": 0.0,
                "events_per_hour_max": 0.0,
                "inter_event_mean_sec": 0.0,
                "inter_event_std_sec": 0.0,
                "max_idle_gap_sec": 0.0,
                "median_idle_gap_sec": 0.0,
                "event_type_entropy": 0.0,
                "burst_max_5min": 0,
            }

        hour_counts: Counter[int] = Counter()
        type_counts: Counter[str] = Counter()
        gaps: list[float] = []
        timestamps = [event.timestamp for event in events]

        for event in events:
            hour_counts[event.timestamp.hour] += 1
            type_counts[event.event_type] += 1

        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if gap >= 0:
                gaps.append(float(gap))

        # Sliding 5-minute burst window (two-pointer, O(n)).
        burst_max = 1
        left = 0
        window = 300.0
        for right in range(len(timestamps)):
            while (timestamps[right] - timestamps[left]).total_seconds() > window:
                left += 1
            burst_max = max(burst_max, right - left + 1)

        hour_values = list(hour_counts.values())
        return {
            "events_per_hour_mean": (sum(hour_values) / len(hour_values)) if hour_values else 0.0,
            "events_per_hour_max": float(max(hour_values)) if hour_values else 0.0,
            "inter_event_mean_sec": (sum(gaps) / len(gaps)) if gaps else 0.0,
            "inter_event_std_sec": _population_std(gaps),
            "max_idle_gap_sec": max(gaps) if gaps else 0.0,
            "median_idle_gap_sec": _median(gaps),
            "event_type_entropy": _shannon_entropy(type_counts),
            "burst_max_5min": burst_max,
        }


class SessionExtractor:
    """Per-session duration and composition features."""

    name = "session"

    def extract(self, events: Sequence[TimelineEventLike]) -> FeatureDict:
        by_session: dict[str, list[TimelineEventLike]] = defaultdict(list)
        for event in events:
            sid = event.session_id or ""
            by_session[sid].append(event)

        if not by_session:
            return {
                "session_count": 0,
                "avg_session_duration_sec": 0.0,
                "max_session_duration_sec": 0.0,
                "avg_events_per_session": 0.0,
                "multi_device_session_count": 0,
            }

        durations: list[float] = []
        event_counts: list[int] = []
        multi_device = 0

        for session_events in by_session.values():
            n = len(session_events)
            event_counts.append(n)
            if n == 1:
                durations.append(0.0)
            else:
                start = session_events[0].timestamp
                end = session_events[-1].timestamp
                durations.append(max(0.0, (end - start).total_seconds()))

            devices = {e.device_id for e in session_events if e.device_id}
            if len(devices) > 1:
                multi_device += 1

        session_count = len(by_session)
        return {
            "session_count": session_count,
            "avg_session_duration_sec": sum(durations) / session_count,
            "max_session_duration_sec": max(durations) if durations else 0.0,
            "avg_events_per_session": sum(event_counts) / session_count,
            "multi_device_session_count": multi_device,
        }


# Default extractor pipeline order (deterministic).
DEFAULT_EXTRACTORS: tuple[FeatureExtractor, ...] = (
    IdentityExtractor(),
    BehaviourExtractor(),
    ResourceExtractor(),
    AuthenticationExtractor(),
    NetworkExtractor(),
    FileActivityExtractor(),
    AttackExtractor(),
    TemporalExtractor(),
    StatisticsExtractor(),
    SessionExtractor(),
)


def run_extractors(
    events: Sequence[TimelineEventLike],
    extractors: Sequence[FeatureExtractor] | None = None,
) -> FeatureDict:
    """Run all extractors and merge their dictionaries (later keys win)."""
    pipeline = extractors if extractors is not None else DEFAULT_EXTRACTORS
    merged: FeatureDict = {}
    for extractor in pipeline:
        merged.update(extractor.extract(events))
    return merged
