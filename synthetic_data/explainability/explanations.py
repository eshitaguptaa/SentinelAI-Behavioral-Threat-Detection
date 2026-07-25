"""Deterministic summary and observation builders for explainability.

Produces SOC-friendly text from risk level and behavioural features only.
Does not modify risk scores and does not read attack ground truth.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Final

BehaviourFeatures = Mapping[str, float]

_SUMMARIES: Final[dict[str, str]] = {
    "LOW": "Employee behaviour appears consistent with historical patterns.",
    "MEDIUM": "Behaviour shows moderate deviations requiring review.",
    "HIGH": "Behaviour indicates elevated security risk.",
    "CRITICAL": "Behaviour strongly suggests potentially malicious activity.",
}

# Fallback when an unexpected level string appears (should not happen in prod).
_DEFAULT_SUMMARY: Final[str] = (
    "Employee activity significantly deviates from normal behavioural patterns."
)


def summary_for_risk_level(risk_level: str) -> str:
    """Return the deterministic summary text for a risk level."""
    return _SUMMARIES.get(risk_level, _DEFAULT_SUMMARY)


def _f(features: BehaviourFeatures, name: str, default: float = 0.0) -> float:
    """Read a behavioural float with a safe default."""
    value = features.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Observation builders (behavioural features only)
# ---------------------------------------------------------------------------


def observe_auth_failure_rate(features: BehaviourFeatures) -> str | None:
    """High authentication failure rate."""
    rate = _f(features, "auth_failure_rate")
    if rate >= 0.50:
        return "Authentication failure rate is unusually high."
    if rate >= 0.25:
        return "Authentication failure rate is elevated."
    return None


def observe_failed_logins(features: BehaviourFeatures) -> str | None:
    """Repeated / multiple failed login attempts."""
    streak = _f(features, "max_failed_login_streak")
    if streak >= 5:
        return "Multiple failed login attempts detected."
    if streak >= 3:
        return "Repeated failed logins detected."
    return None


def observe_country_changes(features: BehaviourFeatures) -> str | None:
    """Cross-country access patterns."""
    changes = _f(features, "country_change_count")
    if changes >= 2:
        return "Access originated from several countries."
    if changes >= 1:
        return "A country change was observed during the day."
    return None


def observe_locations(features: BehaviourFeatures) -> str | None:
    """Multiple locations accessed."""
    unique = _f(features, "unique_location_count")
    changes = _f(features, "location_change_count")
    if unique >= 3 or changes >= 4:
        return "Multiple locations accessed."
    return None


def observe_resource_diversity(features: BehaviourFeatures) -> str | None:
    """High resource diversity."""
    entropy = _f(features, "resource_entropy")
    if entropy >= 2.0:
        return "Resource access diversity exceeded normal behaviour."
    return None


def observe_device_diversity(features: BehaviourFeatures) -> str | None:
    """High device diversity."""
    entropy = _f(features, "device_entropy")
    unique = _f(features, "unique_device_count")
    if entropy >= 1.0 or unique >= 3:
        return "High device diversity observed."
    return None


def observe_download_activity(features: BehaviourFeatures) -> str | None:
    """Large download / mass-download activity."""
    mb = _f(features, "download_size_mb_sum")
    mass = _f(features, "mass_download_event_count")
    if mb >= 100.0 or mass >= 1:
        return "Large download activity detected."
    if mb >= 50.0:
        return "Elevated download volume detected."
    return None


def observe_after_hours(features: BehaviourFeatures) -> str | None:
    """Excessive after-hours activity."""
    count = _f(features, "after_hours_event_count")
    if count >= 10:
        return "Excessive after-hours activity detected."
    if count >= 5:
        return "After-hours activity is elevated."
    return None


def observe_active_duration(features: BehaviourFeatures) -> str | None:
    """Extended active duration."""
    hours = _f(features, "active_duration_hours")
    if hours >= 12.0:
        return "Extended active duration observed."
    return None


def observe_vpn_usage(features: BehaviourFeatures) -> str | None:
    """High VPN usage share."""
    ratio = _f(features, "vpn_usage_ratio")
    if ratio >= 0.60:
        return "High VPN usage observed."
    return None


def observe_activity_burst(features: BehaviourFeatures) -> str | None:
    """Short-window activity burst."""
    burst = _f(features, "burst_max_5min")
    if burst >= 20:
        return "Activity burst detected."
    return None


def observe_file_access(features: BehaviourFeatures) -> str | None:
    """File-access-heavy day."""
    ratio = _f(features, "file_access_ratio")
    if ratio >= 0.60:
        return "File access dominates the day's activity."
    return None


ObservationBuilder = Callable[[BehaviourFeatures], str | None]

# Deterministic observation pipeline order.
OBSERVATION_BUILDERS: tuple[ObservationBuilder, ...] = (
    observe_auth_failure_rate,
    observe_failed_logins,
    observe_country_changes,
    observe_locations,
    observe_resource_diversity,
    observe_device_diversity,
    observe_download_activity,
    observe_after_hours,
    observe_active_duration,
    observe_vpn_usage,
    observe_activity_burst,
    observe_file_access,
)


def build_observations(
    features: BehaviourFeatures,
    *,
    builders: Sequence[ObservationBuilder] | None = None,
) -> list[str]:
    """Build ordered, de-duplicated behavioural observations.

    Only observations supported by the provided behavioural feature map are
    emitted. Empty when no behavioural thresholds are met.
    """
    pipeline = builders if builders is not None else OBSERVATION_BUILDERS
    observations: list[str] = []
    seen: set[str] = set()
    for builder in pipeline:
        text = builder(features)
        if text and text not in seen:
            observations.append(text)
            seen.add(text)
    return observations
