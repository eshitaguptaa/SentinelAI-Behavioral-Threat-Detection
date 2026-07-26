"""Deterministic behavioural risk rules for the SentinelAI Risk Engine.

Each rule:

* evaluates one behavioural condition from ``ml_features()``-compatible maps
* returns a bounded score adjustment
* optionally returns a human-readable contributing-factor explanation

Rules MUST NEVER read attack ground-truth fields. Callers should pass only
behavioural feature dictionaries (e.g. ``FeatureVector.ml_features()``).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

BehaviourFeatures = Mapping[str, float]

# Explicit allow-list of behavioural fields referenced by production rules.
ALLOWED_RULE_FEATURES: Final[frozenset[str]] = frozenset(
    {
        "auth_failure_rate",
        "max_failed_login_streak",
        "country_change_count",
        "location_change_count",
        "resource_entropy",
        "device_entropy",
        "after_hours_event_count",
        "download_size_mb_sum",
        "mass_download_event_count",
        "vpn_usage_ratio",
        "burst_max_5min",
        "active_duration_hours",
        "unique_device_count",
        "unique_location_count",
        "file_access_ratio",
    }
)


@dataclass(slots=True, frozen=True)
class RuleResult:
    """Outcome of a single behavioural risk rule."""

    adjustment: float
    explanation: str | None = None


def _f(features: BehaviourFeatures, name: str, default: float = 0.0) -> float:
    """Read a behavioural float feature with a safe default."""
    value = features.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Individual rules (bounded adjustments)
# ---------------------------------------------------------------------------


def rule_high_anomaly_score(anomaly_score: float) -> RuleResult:
    """Explain elevated anomaly score bands (no feature lookup)."""
    if anomaly_score >= 75.0:
        return RuleResult(0.0, "Critical anomaly score")
    if anomaly_score >= 50.0:
        return RuleResult(0.0, "High anomaly score")
    if anomaly_score >= 25.0:
        return RuleResult(0.0, "Elevated anomaly score")
    return RuleResult(0.0, None)


def rule_auth_failure_rate(features: BehaviourFeatures) -> RuleResult:
    """Penalise elevated authentication failure rates."""
    rate = _f(features, "auth_failure_rate")
    if rate >= 0.50:
        return RuleResult(12.0, "High authentication failure rate")
    if rate >= 0.25:
        return RuleResult(6.0, "Elevated authentication failure rate")
    if rate >= 0.10:
        return RuleResult(2.0, None)
    return RuleResult(0.0, None)


def rule_failed_login_streak(features: BehaviourFeatures) -> RuleResult:
    """Penalise consecutive failed LOGIN attempts."""
    streak = _f(features, "max_failed_login_streak")
    if streak >= 10:
        return RuleResult(14.0, "Multiple failed login attempts")
    if streak >= 5:
        return RuleResult(8.0, "Multiple failed login attempts")
    if streak >= 3:
        return RuleResult(4.0, "Repeated failed login attempts")
    return RuleResult(0.0, None)


def rule_country_changes(features: BehaviourFeatures) -> RuleResult:
    """Penalise frequent cross-country transitions within a day."""
    changes = _f(features, "country_change_count")
    if changes >= 3:
        return RuleResult(15.0, "Frequent country changes")
    if changes >= 2:
        return RuleResult(10.0, "Frequent country changes")
    if changes >= 1:
        return RuleResult(4.0, "Country change detected")
    return RuleResult(0.0, None)


def rule_location_changes(features: BehaviourFeatures) -> RuleResult:
    """Penalise rapid location switching."""
    changes = _f(features, "location_change_count")
    if changes >= 8:
        return RuleResult(8.0, "Frequent location changes")
    if changes >= 4:
        return RuleResult(4.0, "Elevated location changes")
    return RuleResult(0.0, None)


def rule_resource_entropy(features: BehaviourFeatures) -> RuleResult:
    """Penalise unusually high resource-access diversity."""
    entropy = _f(features, "resource_entropy")
    if entropy >= 3.0:
        return RuleResult(8.0, "High resource diversity")
    if entropy >= 2.0:
        return RuleResult(4.0, "Elevated resource diversity")
    return RuleResult(0.0, None)


def rule_device_entropy(features: BehaviourFeatures) -> RuleResult:
    """Penalise diverse device usage within a day."""
    entropy = _f(features, "device_entropy")
    if entropy >= 2.0:
        return RuleResult(8.0, "High device diversity")
    if entropy >= 1.0:
        return RuleResult(3.0, "Elevated device diversity")
    return RuleResult(0.0, None)


def rule_after_hours_activity(features: BehaviourFeatures) -> RuleResult:
    """Penalise excessive after-hours behavioural activity."""
    count = _f(features, "after_hours_event_count")
    if count >= 20:
        return RuleResult(12.0, "Excessive after-hours activity")
    if count >= 10:
        return RuleResult(6.0, "Elevated after-hours activity")
    if count >= 5:
        return RuleResult(2.0, None)
    return RuleResult(0.0, None)


def rule_download_volume(features: BehaviourFeatures) -> RuleResult:
    """Penalise large aggregate download volume."""
    mb = _f(features, "download_size_mb_sum")
    if mb >= 500.0:
        return RuleResult(14.0, "Large download volume")
    if mb >= 100.0:
        return RuleResult(8.0, "Large download volume")
    if mb >= 50.0:
        return RuleResult(3.0, "Elevated download volume")
    return RuleResult(0.0, None)


def rule_mass_download(features: BehaviourFeatures) -> RuleResult:
    """Penalise mass-download indicators."""
    count = _f(features, "mass_download_event_count")
    if count >= 3:
        return RuleResult(12.0, "Mass download activity detected")
    if count >= 1:
        return RuleResult(6.0, "Mass download activity detected")
    return RuleResult(0.0, None)


def rule_vpn_usage(features: BehaviourFeatures) -> RuleResult:
    """Mild adjustment for unusually dominant VPN activity share."""
    ratio = _f(features, "vpn_usage_ratio")
    if ratio >= 0.60:
        return RuleResult(3.0, "High VPN usage share")
    return RuleResult(0.0, None)


def rule_burst_activity(features: BehaviourFeatures) -> RuleResult:
    """Penalise extreme short-window event bursts."""
    burst = _f(features, "burst_max_5min")
    if burst >= 40:
        return RuleResult(10.0, "Extreme activity burst")
    if burst >= 20:
        return RuleResult(5.0, "Elevated activity burst")
    return RuleResult(0.0, None)


def rule_active_duration(features: BehaviourFeatures) -> RuleResult:
    """Penalise abnormally long active sessions within a day."""
    hours = _f(features, "active_duration_hours")
    if hours >= 16.0:
        return RuleResult(6.0, "Abnormally long active duration")
    if hours >= 12.0:
        return RuleResult(3.0, "Extended active duration")
    return RuleResult(0.0, None)


def rule_unique_devices(features: BehaviourFeatures) -> RuleResult:
    """Penalise many distinct devices in one day."""
    count = _f(features, "unique_device_count")
    if count >= 5:
        return RuleResult(8.0, "Multiple devices used")
    if count >= 3:
        return RuleResult(4.0, "Multiple devices used")
    return RuleResult(0.0, None)


def rule_unique_locations(features: BehaviourFeatures) -> RuleResult:
    """Penalise many distinct locations in one day."""
    count = _f(features, "unique_location_count")
    if count >= 4:
        return RuleResult(8.0, "Multiple locations observed")
    if count >= 3:
        return RuleResult(3.0, "Multiple locations observed")
    return RuleResult(0.0, None)


def rule_file_access_ratio(features: BehaviourFeatures) -> RuleResult:
    """Penalise days dominated by file-access activity."""
    ratio = _f(features, "file_access_ratio")
    if ratio >= 0.60:
        return RuleResult(6.0, "File access dominates activity")
    if ratio >= 0.40:
        return RuleResult(2.0, None)
    return RuleResult(0.0, None)


# Ordered rule pipeline (deterministic).
BehaviourRule = Callable[[BehaviourFeatures], RuleResult]

BEHAVIOURAL_RULES: tuple[BehaviourRule, ...] = (
    rule_auth_failure_rate,
    rule_failed_login_streak,
    rule_country_changes,
    rule_location_changes,
    rule_resource_entropy,
    rule_device_entropy,
    rule_after_hours_activity,
    rule_download_volume,
    rule_mass_download,
    rule_vpn_usage,
    rule_burst_activity,
    rule_active_duration,
    rule_unique_devices,
    rule_unique_locations,
    rule_file_access_ratio,
)

# Per-rule absolute adjustment cap (defence in depth; rules already bounded).
MAX_SINGLE_RULE_ADJUSTMENT: float = 15.0
# Cap total behavioural uplift so anomaly score remains the primary signal.
MAX_TOTAL_BEHAVIOURAL_ADJUSTMENT: float = 45.0


def _bound_adjustment(adjustment: float) -> float:
    """Clamp a single-rule adjustment into ``[-MAX, +MAX]`` (positive uplift)."""
    if adjustment < 0.0:
        return 0.0
    if adjustment > MAX_SINGLE_RULE_ADJUSTMENT:
        return MAX_SINGLE_RULE_ADJUSTMENT
    return float(adjustment)


def apply_behavioural_rules(
    features: BehaviourFeatures,
    *,
    rules: Sequence[BehaviourRule] | None = None,
) -> tuple[float, list[str]]:
    """Run all behavioural rules and return ``(total_adjustment, explanations)``.

    Total adjustment is clamped to ``[0, MAX_TOTAL_BEHAVIOURAL_ADJUSTMENT]``.
    Explanations preserve rule order and omit empty strings / duplicates.
    """
    pipeline = rules if rules is not None else BEHAVIOURAL_RULES
    total = 0.0
    factors: list[str] = []
    seen: set[str] = set()

    for rule in pipeline:
        result = rule(features)
        total += _bound_adjustment(result.adjustment)
        explanation = result.explanation
        if explanation and explanation not in seen:
            factors.append(explanation)
            seen.add(explanation)

    if total > MAX_TOTAL_BEHAVIOURAL_ADJUSTMENT:
        total = MAX_TOTAL_BEHAVIOURAL_ADJUSTMENT
    return total, factors


def collect_anomaly_factors(anomaly_score: float) -> list[str]:
    """Return anomaly-score explanations (may be empty for low scores)."""
    result = rule_high_anomaly_score(anomaly_score)
    if result.explanation:
        return [result.explanation]
    return []
