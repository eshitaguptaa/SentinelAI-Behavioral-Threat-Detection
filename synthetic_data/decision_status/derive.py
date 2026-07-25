"""Single decision hierarchy for SentinelAI final status.

Status is derived from ``risk_level`` AND ``attack_type``.
``Normal Activity`` is never promoted to ``Confirmed Threat``.
"""

from __future__ import annotations

from synthetic_data.decision_status.schema import (
    NORMAL_ATTACK_TYPE,
    FinalStatus,
)


def derive_final_status(risk_level: str, attack_type: str) -> str:
    """Derive the final SOC status from risk level and attack classification.

    Hierarchy (deterministic)::

        Normal Activity + LOW       → Normal
        Normal Activity + MEDIUM    → Suspicious
        Normal Activity + HIGH/CRIT → Under Investigation
        Other attack + MEDIUM       → Suspicious
        Other attack + HIGH/CRIT    → Confirmed Threat
        Other attack + LOW          → Suspicious

    ``Normal Activity`` never yields ``Confirmed Threat``.
    """
    level = (risk_level or "").strip().upper()
    attack = (attack_type or "").strip()
    is_normal = attack == NORMAL_ATTACK_TYPE or attack == ""

    if is_normal:
        if level == "LOW":
            return FinalStatus.NORMAL.value
        if level == "MEDIUM":
            return FinalStatus.SUSPICIOUS.value
        # HIGH / CRITICAL / unknown elevated → investigate, never confirm
        return FinalStatus.UNDER_INVESTIGATION.value

    # Known attack pattern labelled by the rule-based classifier
    if level in {"HIGH", "CRITICAL"}:
        return FinalStatus.CONFIRMED_THREAT.value
    return FinalStatus.SUSPICIOUS.value
