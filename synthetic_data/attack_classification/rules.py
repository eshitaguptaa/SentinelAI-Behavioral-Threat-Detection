"""Deterministic attack-classification rules (no machine learning).

Each rule inspects behavioural features from ``FeatureVector.ml_features()``
and returns whether it matches plus a confidence and signal list.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from synthetic_data.attack_classification.schema import AttackType

BehaviourFeatures = Mapping[str, float]


@dataclass(slots=True, frozen=True)
class RuleMatch:
    """Outcome of evaluating one classification rule."""

    matched: bool
    attack_type: AttackType
    confidence: float
    signals: tuple[str, ...] = ()


def _f(features: BehaviourFeatures, name: str, default: float = 0.0) -> float:
    value = features.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Thresholds (deterministic, documented)
# ---------------------------------------------------------------------------

COUNTRY_CHANGE_MIN = 2
BRUTE_AUTH_FAILURE_MIN = 0.4
BRUTE_STREAK_MIN = 5
STUFFING_AUTH_FAILURE_MIN = 0.25
STUFFING_LOGIN_COUNT_MIN = 10
MASS_DOWNLOAD_MB_MIN = 100.0
DEVICE_COUNT_MIN = 4
DEVICE_ENTROPY_MIN = 1.0
INSIDER_AFTER_HOURS_MIN = 10
INSIDER_DURATION_HOURS_MIN = 12.0
INSIDER_FILE_RATIO_MIN = 0.40
VPN_RATIO_MIN = 0.60
LATERAL_UNIQUE_LOC_MIN = 3
LATERAL_LOC_CHANGE_MIN = 4
# Low-and-slow: meaningful volume without a burst signature.
LOW_SLOW_MB_MIN = 12.0
LOW_SLOW_MB_MAX = 95.0
LOW_SLOW_IDLE_GAP_MIN = 600.0
LOW_SLOW_BURST_MAX = 8
LOW_SLOW_DURATION_MIN = 3.0
# Insider drift: expanding footprint without after-hours / mass-download cues.
DRIFT_RESOURCE_MIN = 6
DRIFT_ENTROPY_MIN = 1.5
DRIFT_SWITCH_MIN = 5
DRIFT_AFTER_HOURS_MAX = 8
DRIFT_MASS_DOWNLOAD_MAX = 0


def rule_impossible_travel(features: BehaviourFeatures) -> RuleMatch:
    """Impossible Travel — rapid multi-country transitions."""
    changes = _f(features, "country_change_count")
    if changes >= COUNTRY_CHANGE_MIN:
        return RuleMatch(
            True,
            AttackType.IMPOSSIBLE_TRAVEL,
            0.88,
            (f"country_change_count={changes:.0f}",),
        )
    return RuleMatch(False, AttackType.IMPOSSIBLE_TRAVEL, 0.0)


def rule_brute_force(features: BehaviourFeatures) -> RuleMatch:
    """Brute Force — elevated failures with a long failure streak."""
    rate = _f(features, "auth_failure_rate")
    streak = _f(features, "max_failed_login_streak")
    if rate > BRUTE_AUTH_FAILURE_MIN and streak >= BRUTE_STREAK_MIN:
        return RuleMatch(
            True,
            AttackType.BRUTE_FORCE,
            0.92,
            (
                f"auth_failure_rate={rate:.2f}",
                f"max_failed_login_streak={streak:.0f}",
            ),
        )
    return RuleMatch(False, AttackType.BRUTE_FORCE, 0.0)


def rule_credential_stuffing(features: BehaviourFeatures) -> RuleMatch:
    """Credential Stuffing — many logins with moderate failure rate."""
    rate = _f(features, "auth_failure_rate")
    logins = _f(features, "login_count")
    if rate > STUFFING_AUTH_FAILURE_MIN and logins > STUFFING_LOGIN_COUNT_MIN:
        return RuleMatch(
            True,
            AttackType.CREDENTIAL_STUFFING,
            0.84,
            (
                f"auth_failure_rate={rate:.2f}",
                f"login_count={logins:.0f}",
            ),
        )
    return RuleMatch(False, AttackType.CREDENTIAL_STUFFING, 0.0)


def rule_mass_download(features: BehaviourFeatures) -> RuleMatch:
    """Mass Download — large volume with mass-download indicators."""
    mb = _f(features, "download_size_mb_sum")
    mass = _f(features, "mass_download_event_count")
    if mb > MASS_DOWNLOAD_MB_MIN and mass > 0:
        return RuleMatch(
            True,
            AttackType.MASS_DOWNLOAD,
            0.90,
            (
                f"download_size_mb_sum={mb:.1f}",
                f"mass_download_event_count={mass:.0f}",
            ),
        )
    return RuleMatch(False, AttackType.MASS_DOWNLOAD, 0.0)


def rule_device_spoofing(features: BehaviourFeatures) -> RuleMatch:
    """Device Spoofing — many devices with high device entropy."""
    devices = _f(features, "unique_device_count")
    entropy = _f(features, "device_entropy")
    if devices >= DEVICE_COUNT_MIN and entropy >= DEVICE_ENTROPY_MIN:
        return RuleMatch(
            True,
            AttackType.DEVICE_SPOOFING,
            0.80,
            (
                f"unique_device_count={devices:.0f}",
                f"device_entropy={entropy:.2f}",
            ),
        )
    return RuleMatch(False, AttackType.DEVICE_SPOOFING, 0.0)


def rule_lateral_movement(features: BehaviourFeatures) -> RuleMatch:
    """Lateral Movement — many locations with frequent switches."""
    unique = _f(features, "unique_location_count")
    changes = _f(features, "location_change_count")
    if unique >= LATERAL_UNIQUE_LOC_MIN and changes >= LATERAL_LOC_CHANGE_MIN:
        return RuleMatch(
            True,
            AttackType.LATERAL_MOVEMENT,
            0.82,
            (
                f"unique_location_count={unique:.0f}",
                f"location_change_count={changes:.0f}",
            ),
        )
    return RuleMatch(False, AttackType.LATERAL_MOVEMENT, 0.0)


def rule_low_and_slow(features: BehaviourFeatures) -> RuleMatch:
    """Low-and-Slow Exfiltration — gradual volume with long idle gaps."""
    mb = _f(features, "download_size_mb_sum")
    idle = _f(features, "median_idle_gap_sec")
    burst = _f(features, "burst_max_5min")
    duration = _f(features, "active_duration_hours")
    mass = _f(features, "mass_download_event_count")
    if (
        LOW_SLOW_MB_MIN <= mb <= LOW_SLOW_MB_MAX
        and idle >= LOW_SLOW_IDLE_GAP_MIN
        and burst <= LOW_SLOW_BURST_MAX
        and duration >= LOW_SLOW_DURATION_MIN
        and mass <= 0
    ):
        return RuleMatch(
            True,
            AttackType.LOW_AND_SLOW_EXFIL,
            0.81,
            (
                f"download_size_mb_sum={mb:.1f}",
                f"median_idle_gap_sec={idle:.0f}",
                f"burst_max_5min={burst:.0f}",
                f"active_duration_hours={duration:.1f}",
            ),
        )
    return RuleMatch(False, AttackType.LOW_AND_SLOW_EXFIL, 0.0)


def rule_insider_drift(features: BehaviourFeatures) -> RuleMatch:
    """Insider Drift — expanding resource footprint without hard attack cues."""
    resources = _f(features, "unique_resource_count")
    entropy = _f(features, "resource_entropy")
    switches = _f(features, "resource_switch_count")
    after_hours = _f(features, "after_hours_event_count")
    mass = _f(features, "mass_download_event_count")
    if (
        resources >= DRIFT_RESOURCE_MIN
        and entropy >= DRIFT_ENTROPY_MIN
        and switches >= DRIFT_SWITCH_MIN
        and after_hours <= DRIFT_AFTER_HOURS_MAX
        and mass <= DRIFT_MASS_DOWNLOAD_MAX
    ):
        return RuleMatch(
            True,
            AttackType.INSIDER_DRIFT,
            0.62,
            (
                f"unique_resource_count={resources:.0f}",
                f"resource_entropy={entropy:.2f}",
                f"resource_switch_count={switches:.0f}",
            ),
        )
    return RuleMatch(False, AttackType.INSIDER_DRIFT, 0.0)


def rule_insider_activity(features: BehaviourFeatures) -> RuleMatch:
    """Insider Activity — after-hours, long session, file-heavy access."""
    after_hours = _f(features, "after_hours_event_count")
    duration = _f(features, "active_duration_hours")
    file_ratio = _f(features, "file_access_ratio")
    if (
        after_hours >= INSIDER_AFTER_HOURS_MIN
        and duration >= INSIDER_DURATION_HOURS_MIN
        and file_ratio >= INSIDER_FILE_RATIO_MIN
    ):
        return RuleMatch(
            True,
            AttackType.INSIDER_ACTIVITY,
            0.78,
            (
                f"after_hours_event_count={after_hours:.0f}",
                f"active_duration_hours={duration:.1f}",
                f"file_access_ratio={file_ratio:.2f}",
            ),
        )
    return RuleMatch(False, AttackType.INSIDER_ACTIVITY, 0.0)


def rule_suspicious_vpn(features: BehaviourFeatures) -> RuleMatch:
    """Suspicious VPN Usage — VPN dominates the day's activity share."""
    ratio = _f(features, "vpn_usage_ratio")
    if ratio >= VPN_RATIO_MIN:
        return RuleMatch(
            True,
            AttackType.SUSPICIOUS_VPN_USAGE,
            0.70,
            (f"vpn_usage_ratio={ratio:.2f}",),
        )
    return RuleMatch(False, AttackType.SUSPICIOUS_VPN_USAGE, 0.0)


ClassificationRule = Callable[[BehaviourFeatures], RuleMatch]

# Priority order: first match wins (deterministic).
CLASSIFICATION_RULES: tuple[ClassificationRule, ...] = (
    rule_impossible_travel,
    rule_brute_force,
    rule_credential_stuffing,
    rule_mass_download,
    rule_device_spoofing,
    rule_lateral_movement,
    rule_low_and_slow,
    rule_insider_activity,
    rule_insider_drift,
    rule_suspicious_vpn,
)


def evaluate_rules(
    features: BehaviourFeatures,
    *,
    rules: Sequence[ClassificationRule] | None = None,
    anomaly_score: float | None = None,
) -> RuleMatch:
    """Return the first matching signature rule, or a non-signature label.

    When no rule matches, the label depends on ``anomaly_score``::

        ≤ LOW band          → None
        MEDIUM band         → Unknown Behaviour
        HIGH / CRITICAL     → Behavioural Anomaly

    ``Normal Activity`` is never returned.
    """
    from synthetic_data.attack_classification.labeling import (
        resolve_unmatched_attack_type,
    )

    pipeline = rules if rules is not None else CLASSIFICATION_RULES
    for rule in pipeline:
        result = rule(features)
        if result.matched:
            return result

    score = 0.0 if anomaly_score is None else float(anomaly_score)
    label = resolve_unmatched_attack_type(score)
    signals: tuple[str, ...]
    if label is AttackType.NONE:
        signals = ("no_attack_rule_matched", "anomaly_within_normal_band")
    elif label is AttackType.UNKNOWN_BEHAVIOUR:
        signals = ("no_attack_rule_matched", "moderate_reconstruction_anomaly")
    else:
        signals = ("no_attack_rule_matched", "elevated_reconstruction_anomaly")
    return RuleMatch(True, label, 0.0, signals)
