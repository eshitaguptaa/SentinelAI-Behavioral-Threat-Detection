"""Attack-aware SOC recommendations."""

from __future__ import annotations

from typing import Final

from synthetic_data.decision_status.schema import NORMAL_ATTACK_TYPE
from synthetic_data.risk_engine.schema import RiskLevel

_ATTACK_RECOMMENDATIONS: Final[dict[str, str]] = {
    "Credential Stuffing": (
        "Reset password; review MFA enrolment; inspect authentication logs "
        "for spray/stuffing patterns."
    ),
    "Brute Force": (
        "Block or rate-limit the source IP; review authentication attempts; "
        "enforce lockout / MFA challenges."
    ),
    "Lateral Movement": (
        "Isolate the endpoint; review lateral authentication and remote "
        "service access (SSH/RDP); hunt for additional compromised hosts."
    ),
    "Impossible Travel": (
        "Invalidate active sessions; require step-up MFA; verify recent "
        "login geography with the user."
    ),
    "Device Spoofing": (
        "Verify the endpoint; re-enrol a trusted device; revoke untrusted "
        "device certificates."
    ),
    "Insider Activity": (
        "Review sensitive file and USB activity; interview the user; "
        "temporarily restrict high-risk data access."
    ),
    "Mass Download": (
        "Throttle or block bulk downloads; review DLP alerts; confirm "
        "business justification for transferred data."
    ),
    "Suspicious VPN Usage": (
        "Review VPN session posture; verify tunnel endpoints; require "
        "re-authentication if the pattern persists."
    ),
    NORMAL_ATTACK_TYPE: "Continue monitoring.",
}

_LEVEL_FALLBACK: Final[dict[str, str]] = {
    RiskLevel.LOW.value: "Continue monitoring.",
    RiskLevel.MEDIUM.value: (
        "Review recent authentication and user activity; escalate if "
        "behaviour persists."
    ),
    RiskLevel.HIGH.value: (
        "Open an SOC investigation; collect session evidence and correlate "
        "with authentication logs."
    ),
    RiskLevel.CRITICAL.value: "Immediate incident response required.",
}


def recommendation_for_attack(
    attack_type: str,
    *,
    risk_level: str | None = None,
) -> str:
    """Return an attack-specific recommendation (falls back to risk level)."""
    attack = (attack_type or "").strip()
    if attack in _ATTACK_RECOMMENDATIONS:
        return _ATTACK_RECOMMENDATIONS[attack]
    level = (risk_level or RiskLevel.MEDIUM.value).strip().upper()
    return _LEVEL_FALLBACK.get(
        level,
        _LEVEL_FALLBACK[RiskLevel.MEDIUM.value],
    )
