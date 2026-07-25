"""Single decision hierarchy for SentinelAI final status.

Status depends on **risk score**, **signature attack rule match**, and
**model confidence** — not on risk_level alone. Thresholds live in
``RiskEngineConfig``.
"""

from __future__ import annotations

from synthetic_data.decision_status.schema import (
    NON_SIGNATURE_ATTACK_TYPES,
    FinalStatus,
    is_signature_attack,
)
from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG, RiskEngineConfig


def _as_percent(value: float) -> float:
    """Normalise confidence provided as 0–1 or 0–100 into percent."""
    number = float(value)
    if number <= 1.0:
        number *= 100.0
    return max(0.0, min(100.0, number))


def derive_final_status(
    risk_level_or_score: str | float,
    attack_type: str | None = None,
    confidence: float | None = None,
    *,
    risk_score: float | None = None,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> str:
    """Derive the final SOC status.

    Preferred call (SOC workflow)::

        derive_final_status(risk_score, attack_type, confidence)

    Hierarchy (deterministic, from ``RiskEngineConfig``)::

        IF signature_attack_rule_matched
           AND risk >= confirmed_risk_min
           AND confidence >= confirmed_confidence_min
            → Confirmed Threat
        ELSE IF risk >= investigate_risk_min
            → Under Investigation
        ELSE IF risk >= suspicious_risk_min
            → Suspicious
        ELSE
            → Normal

    ``None`` / ``Behavioural Anomaly`` / ``Unknown Behaviour`` never yield
    ``Confirmed Threat`` (no signature rule match).
    """
    if risk_score is not None:
        score = float(risk_score)
    elif isinstance(risk_level_or_score, (int, float)):
        score = float(risk_level_or_score)
    else:
        level = str(risk_level_or_score or "").strip().upper()
        legacy_map = {
            "LOW": 20.0,
            "MEDIUM": 40.0,
            "HIGH": 65.0,
            "CRITICAL": 90.0,
        }
        score = legacy_map.get(level, 0.0)

    rule_matched = is_signature_attack(attack_type)
    conf_pct = _as_percent(confidence) if confidence is not None else 0.0

    if (
        rule_matched
        and score >= config.confirmed_risk_min
        and conf_pct >= config.confirmed_confidence_min
    ):
        return FinalStatus.CONFIRMED_THREAT.value

    if score >= config.investigate_risk_min:
        return FinalStatus.UNDER_INVESTIGATION.value

    if score >= config.suspicious_risk_min:
        return FinalStatus.SUSPICIOUS.value

    return FinalStatus.NORMAL.value


def status_decision_reason(
    *,
    risk_score: float,
    attack_type: str,
    confidence: float,
    status: str,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> str:
    """Human-readable reason string for the SOC decision."""
    conf = _as_percent(confidence)
    attack = (attack_type or "").strip() or "None"
    rule_matched = is_signature_attack(attack)

    if status == FinalStatus.CONFIRMED_THREAT.value:
        return (
            f"Attack rule matched ({attack}). "
            f"Risk {risk_score:.0f} and confidence {conf:.0f}% both meet "
            f"confirmation thresholds "
            f"(≥{config.confirmed_risk_min:.0f} / ≥{config.confirmed_confidence_min:.0f}%)."
        )
    if status == FinalStatus.UNDER_INVESTIGATION.value:
        if rule_matched and conf < config.confirmed_confidence_min:
            return (
                f"Rule matched ({attack}) but confidence is below the "
                f"confirmation threshold ({conf:.0f}% < "
                f"{config.confirmed_confidence_min:.0f}%). "
                f"Risk {risk_score:.0f} warrants investigation."
            )
        if rule_matched and risk_score < config.confirmed_risk_min:
            return (
                f"Rule matched ({attack}) but risk {risk_score:.0f} is below "
                f"the confirmation threshold ({config.confirmed_risk_min:.0f})."
            )
        if attack in NON_SIGNATURE_ATTACK_TYPES and attack not in {"", "None"}:
            return (
                f"No known attack signature matched ({attack}). "
                f"Risk {risk_score:.0f} is at or above the investigation threshold "
                f"({config.investigate_risk_min:.0f})."
            )
        return (
            f"Risk {risk_score:.0f} is at or above the investigation threshold "
            f"({config.investigate_risk_min:.0f})."
        )
    if status == FinalStatus.SUSPICIOUS.value:
        return (
            f"Risk {risk_score:.0f} is elevated "
            f"(≥{config.suspicious_risk_min:.0f}) but below investigation."
        )
    return (
        f"Risk {risk_score:.0f} is below the suspicious threshold "
        f"({config.suspicious_risk_min:.0f}); behaviour looks routine."
    )
