"""Deterministic summary and observation builders for explainability.

Produces evidence-based SOC narratives from risk level, attack type, and
behavioural features. Does not modify risk scores.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Final

from synthetic_data.decision_status.schema import NORMAL_ATTACK_TYPE

BehaviourFeatures = Mapping[str, float]

_ATTACK_SUMMARIES: Final[dict[str, str]] = {
    "Brute Force": "High failed-login ratio consistent with brute-force authentication attacks.",
    "Credential Stuffing": (
        "Multiple failed logins followed by successful authentication, "
        "consistent with credential stuffing."
    ),
    "Impossible Travel": (
        "Logins from geographically impossible locations within the observed window."
    ),
    "Lateral Movement": (
        "Multiple hosts or remote services accessed within a short time, "
        "consistent with lateral movement."
    ),
    "Device Spoofing": "Activity from an unknown or untrusted device fingerprint.",
    "Insider Activity": (
        "Sensitive reads followed by removable-media or bulk transfer signals."
    ),
    "Mass Download": "Abnormally large file download volume for this employee baseline.",
    "Suspicious VPN Usage": (
        "VPN usage patterns inconsistent with the employee's normal access posture."
    ),
}

_NORMAL_SUMMARIES: Final[dict[str, str]] = {
    "LOW": (
        "No known attack pattern was detected. Behaviour is consistent with "
        "the employee's historical patterns."
    ),
    "MEDIUM": (
        "No known attack pattern was detected. The Transformer observed "
        "moderate deviation from the employee's historical behaviour."
    ),
    "HIGH": (
        "No known attack pattern was detected. The Transformer observed "
        "elevated deviation from the employee's historical behaviour; "
        "manual review is recommended."
    ),
    "CRITICAL": (
        "No known attack pattern was detected, but reconstruction error is "
        "extreme relative to the employee's baseline. Treat as under "
        "investigation until confirmed."
    ),
}


def summary_for_detection(
    *,
    risk_level: str,
    attack_type: str,
    matched_signals: Sequence[str] | None = None,
) -> str:
    """Build an evidence-based summary for the SOC panel."""
    attack = (attack_type or "").strip() or NORMAL_ATTACK_TYPE
    level = (risk_level or "LOW").strip().upper()

    if attack != NORMAL_ATTACK_TYPE:
        base = _ATTACK_SUMMARIES.get(
            attack,
            f"Behavioural evidence supports classification as {attack}.",
        )
        signals = [s for s in (matched_signals or []) if s]
        if signals:
            return f"{base} Evidence: {'; '.join(signals[:3])}."
        return base

    return _NORMAL_SUMMARIES.get(level, _NORMAL_SUMMARIES["MEDIUM"])


def summary_for_risk_level(risk_level: str) -> str:
    """Backward-compatible summary when attack type is unavailable."""
    return summary_for_detection(
        risk_level=risk_level,
        attack_type=NORMAL_ATTACK_TYPE,
    )


def _f(features: BehaviourFeatures, name: str, default: float = 0.0) -> float:
    """Read a behavioural float with a safe default."""
    value = features.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def observe_auth_failure_rate(features: BehaviourFeatures) -> str | None:
    rate = _f(features, "auth_failure_rate")
    if rate >= 0.50:
        return f"Authentication failure rate is {rate:.0%} (unusually high)."
    if rate >= 0.25:
        return f"Authentication failure rate is elevated ({rate:.0%})."
    return None


def observe_failed_logins(features: BehaviourFeatures) -> str | None:
    streak = _f(features, "max_failed_login_streak")
    if streak >= 5:
        return f"Failed-login streak of {int(streak)} attempts detected."
    if streak >= 3:
        return f"Repeated failed logins (streak={int(streak)})."
    return None


def observe_country_changes(features: BehaviourFeatures) -> str | None:
    changes = _f(features, "country_change_count")
    if changes >= 2:
        return f"Access originated from {int(changes)} country changes."
    if changes >= 1:
        return "A country change was observed during the day."
    return None


def observe_locations(features: BehaviourFeatures) -> str | None:
    unique = _f(features, "unique_location_count")
    changes = _f(features, "location_change_count")
    if unique >= 3 or changes >= 4:
        return (
            f"Multiple locations accessed "
            f"(unique={int(unique)}, changes={int(changes)})."
        )
    return None


def observe_resource_diversity(features: BehaviourFeatures) -> str | None:
    entropy = _f(features, "resource_entropy")
    if entropy >= 2.0:
        return f"Resource access entropy elevated ({entropy:.2f})."
    return None


def observe_device_diversity(features: BehaviourFeatures) -> str | None:
    entropy = _f(features, "device_entropy")
    unique = _f(features, "unique_device_count")
    if entropy >= 1.0 or unique >= 3:
        return f"High device diversity (devices={int(unique)}, entropy={entropy:.2f})."
    return None


def observe_download_activity(features: BehaviourFeatures) -> str | None:
    mb = _f(features, "download_size_mb_sum")
    mass = _f(features, "mass_download_event_count")
    if mb >= 100.0 or mass >= 1:
        return f"Large download activity detected ({mb:.0f} MB)."
    if mb >= 50.0:
        return f"Elevated download volume ({mb:.0f} MB)."
    return None


def observe_after_hours(features: BehaviourFeatures) -> str | None:
    count = _f(features, "after_hours_event_count")
    if count >= 10:
        return f"Excessive after-hours activity ({int(count)} events)."
    if count >= 5:
        return f"After-hours activity is elevated ({int(count)} events)."
    return None


def observe_active_duration(features: BehaviourFeatures) -> str | None:
    hours = _f(features, "active_duration_hours")
    if hours >= 12.0:
        return f"Extended active duration ({hours:.1f}h)."
    return None


def observe_vpn_usage(features: BehaviourFeatures) -> str | None:
    ratio = _f(features, "vpn_usage_ratio")
    if ratio >= 0.60:
        return f"High VPN usage share ({ratio:.0%})."
    return None


def observe_activity_burst(features: BehaviourFeatures) -> str | None:
    burst = _f(features, "burst_max_5min")
    if burst >= 20:
        return f"Activity burst detected (max {int(burst)} events / 5 min)."
    return None


def observe_file_access(features: BehaviourFeatures) -> str | None:
    ratio = _f(features, "file_access_ratio")
    if ratio >= 0.60:
        return f"File access dominates the day ({ratio:.0%} of activity)."
    return None


ObservationBuilder = Callable[[BehaviourFeatures], str | None]

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
    """Build ordered, de-duplicated behavioural observations."""
    pipeline = builders if builders is not None else OBSERVATION_BUILDERS
    observations: list[str] = []
    seen: set[str] = set()
    for builder in pipeline:
        text = builder(features)
        if text and text not in seen:
            observations.append(text)
            seen.add(text)
    return observations
