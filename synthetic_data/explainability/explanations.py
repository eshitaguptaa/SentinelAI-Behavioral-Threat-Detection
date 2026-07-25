"""Deterministic summary and observation builders for explainability.

Produces evidence-based SOC narratives that distinguish Transformer findings
from rule findings. Does not modify risk scores.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from synthetic_data.decision_status.derive import status_decision_reason
from synthetic_data.decision_status.schema import (
    NORMAL_ATTACK_TYPE,
    is_signature_attack,
)
from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG

BehaviourFeatures = Mapping[str, float]

_ATTACK_RULE_LABELS: Final[dict[str, str]] = {
    "Brute Force": "Brute-force authentication pattern matched",
    "Credential Stuffing": "Credential-stuffing pattern matched",
    "Impossible Travel": "Impossible-travel pattern matched",
    "Lateral Movement": "Lateral-movement pattern matched",
    "Device Spoofing": "Device-spoofing pattern matched",
    "Insider Activity": "Insider-activity pattern matched",
    "Mass Download": "Mass-download pattern matched",
    "Suspicious VPN Usage": "Suspicious VPN usage pattern matched",
}


def _f(features: BehaviourFeatures, name: str, default: float = 0.0) -> float:
    value = features.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_transformer_findings(
    *,
    anomaly_score: float,
    behaviour_insight: Mapping[str, Any] | None = None,
) -> list[str]:
    """Model-centric findings (reconstruction / attention), not rule text."""
    findings: list[str] = []
    score = float(anomaly_score)

    if score >= 75.0:
        findings.append("Reconstruction error is unusually high relative to training normals")
        findings.append("Session differs significantly from learned behaviour")
    elif score >= 50.0:
        findings.append("Reconstruction error is elevated versus the training distribution")
        findings.append("Session shows notable deviation from learned behaviour")
    elif score >= 25.0:
        findings.append("Reconstruction error is moderately above the normal bulk")
    else:
        findings.append("Reconstruction error is consistent with normal training sessions")

    insight = dict(behaviour_insight or {})
    top_events = list(insight.get("top_suspicious_events") or [])
    if top_events:
        top = top_events[0]
        event_type = str(top.get("event_type") or "event")
        findings.append(f"Highest attention / reconstruction contribution on {event_type}")
    elif insight.get("attention_available") and insight.get("event_types"):
        # Fall back to max attention mass row if ranked list empty.
        weights = insight.get("attention_weights") or []
        labels = list(insight.get("event_types") or [])
        best_idx = -1
        best_mass = -1.0
        for index, row in enumerate(weights):
            if index >= len(labels):
                break
            mass = float(sum(row)) if row else 0.0
            if mass > best_mass:
                best_mass = mass
                best_idx = index
        if best_idx >= 0:
            findings.append(
                f"Highest attention mass on {labels[best_idx]}"
            )

    recon = insight.get("reconstruction_error")
    if recon is not None:
        findings.append(f"Session reconstruction error = {float(recon):.3f}")

    # De-dupe preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for item in findings:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def build_rule_findings(
    features: BehaviourFeatures,
    *,
    attack_type: str,
    matched_signals: Sequence[str] | None = None,
) -> list[str]:
    """Rule-engine findings from attack classification + behavioural signals."""
    findings: list[str] = []
    attack = (attack_type or "").strip() or "None"

    if is_signature_attack(attack):
        findings.append(
            _ATTACK_RULE_LABELS.get(attack, f"Attack rule matched: {attack}")
        )
        for signal in matched_signals or []:
            if signal:
                findings.append(str(signal))
    elif attack == "Behavioural Anomaly":
        findings.append("No attack-classification rule matched")
        findings.append("Labelled Behavioural Anomaly from elevated Transformer score")
    elif attack == "Unknown Behaviour":
        findings.append("No attack-classification rule matched")
        findings.append("Labelled Unknown Behaviour from moderate Transformer score")
    else:
        findings.append("No attack-classification rule matched")

    # Concrete behavioural evidence (rule-oriented, not Transformer).
    mb = _f(features, "download_size_mb_sum")
    mass = _f(features, "mass_download_event_count")
    if mb >= 50.0 or mass >= 1:
        findings.append(f"Download volume {mb:.0f} MB")
    if mass >= 1:
        findings.append(f"Mass-download indicators = {int(mass)}")

    rate = _f(features, "auth_failure_rate")
    streak = _f(features, "max_failed_login_streak")
    if rate >= 0.25:
        findings.append(f"Authentication failure rate {rate:.0%}")
    if streak >= 3:
        findings.append(f"Failed-login streak {int(streak)}")

    countries = _f(features, "country_change_count")
    if countries >= 1:
        findings.append(f"Country changes = {int(countries)}")

    devices = _f(features, "unique_device_count")
    if devices >= 3:
        findings.append(f"Unique devices = {int(devices)}")

    after = _f(features, "after_hours_event_count")
    if after >= 5:
        findings.append(f"After-hours events = {int(after)}")

    seen: set[str] = set()
    ordered: list[str] = []
    for item in findings:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def build_decision_summary(
    *,
    status: str,
    risk_score: float,
    attack_type: str,
    confidence: float,
    transformer_findings: Sequence[str],
    rule_findings: Sequence[str],
) -> str:
    """Compose the SOC panel summary: Decision + Reason."""
    reason = status_decision_reason(
        risk_score=risk_score,
        attack_type=attack_type,
        confidence=confidence,
        status=status,
        config=DEFAULT_RISK_CONFIG,
    )
    conf = float(confidence)
    if conf <= 1.0:
        conf *= 100.0
    lines = [
        f"Decision: {status}",
        f"Reason: {reason}",
    ]
    if transformer_findings:
        lines.append("Transformer findings: " + "; ".join(transformer_findings[:3]))
    if rule_findings:
        lines.append("Rule findings: " + "; ".join(rule_findings[:3]))
    return " ".join(lines)


# ---------------------------------------------------------------------------
# Legacy observation builders (still used as rule-finding supplements)
# ---------------------------------------------------------------------------


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
    """Build ordered, de-duplicated behavioural observations (legacy helper)."""
    pipeline = builders if builders is not None else OBSERVATION_BUILDERS
    observations: list[str] = []
    seen: set[str] = set()
    for builder in pipeline:
        text = builder(features)
        if text and text not in seen:
            observations.append(text)
            seen.add(text)
    return observations


def summary_for_detection(
    *,
    risk_level: str,
    attack_type: str,
    matched_signals: Sequence[str] | None = None,
    status: str | None = None,
    risk_score: float | None = None,
    confidence: float | None = None,
) -> str:
    """Build an evidence-based summary for the SOC panel."""
    attack = (attack_type or "").strip() or "None"
    if status and risk_score is not None and confidence is not None:
        return build_decision_summary(
            status=status,
            risk_score=float(risk_score),
            attack_type=attack,
            confidence=float(confidence),
            transformer_findings=[],
            rule_findings=list(matched_signals or [])[:3],
        )

    # Fallback when status/confidence not supplied (unit tests / legacy).
    level = (risk_level or "LOW").strip().upper()
    if is_signature_attack(attack):
        label = _ATTACK_RULE_LABELS.get(
            attack, f"Behavioural evidence supports classification as {attack}."
        )
        signals = [s for s in (matched_signals or []) if s]
        if signals:
            return f"{label}. Evidence: {'; '.join(signals[:3])}."
        return label
    if attack == "Behavioural Anomaly":
        return (
            "No known attack signature matched. Transformer reconstruction "
            "error indicates a behavioural anomaly."
        )
    if attack == "Unknown Behaviour":
        return (
            "No known attack signature matched. Transformer observed moderate "
            "deviation from learned behaviour."
        )
    return {
        "LOW": "No known attack pattern was detected. Behaviour looks routine.",
        "MEDIUM": "No known attack pattern was detected. Moderate behavioural deviation.",
        "HIGH": "No known attack pattern was detected. Elevated deviation — investigate.",
        "CRITICAL": "No known attack pattern was detected. Extreme deviation — investigate.",
    }.get(level, "No known attack pattern was detected.")


def summary_for_risk_level(risk_level: str) -> str:
    """Backward-compatible summary when attack type is unavailable."""
    return summary_for_detection(
        risk_level=risk_level,
        attack_type=NORMAL_ATTACK_TYPE,
    )
