"""Single decision hierarchy for SentinelAI final status.

Status is derived ONLY from ``risk_level`` and ``attack_type``.
It must never be taken from Isolation Forest ``is_anomaly`` alone.
"""

from __future__ import annotations

from synthetic_data.decision_status.schema import (
    NORMAL_ATTACK_TYPE,
    FinalStatus,
)


def derive_final_status(risk_level: str, attack_type: str) -> str:
    """Derive the final SOC status from risk level and attack classification.

    Hierarchy (deterministic)::

        HIGH / CRITICAL           → Confirmed Threat
        MEDIUM                    → Suspicious
        LOW + Normal Activity     → Normal
        LOW + any other attack    → Suspicious

    Args:
        risk_level: ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``.
        attack_type: Attack classification label (e.g. ``Brute Force``).

    Returns:
        One of ``Normal``, ``Suspicious``, ``Confirmed Threat``.
    """
    level = (risk_level or "").strip().upper()
    attack = (attack_type or "").strip()

    if level in {"HIGH", "CRITICAL"}:
        return FinalStatus.CONFIRMED_THREAT.value

    if level == "MEDIUM":
        # Medium risk is always abnormal enough for SOC review.
        return FinalStatus.SUSPICIOUS.value

    # LOW (and any unexpected band treated as LOW-safe path)
    if attack == NORMAL_ATTACK_TYPE or attack == "":
        return FinalStatus.NORMAL.value
    return FinalStatus.SUSPICIOUS.value
