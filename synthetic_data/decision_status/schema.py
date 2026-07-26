"""Final SOC status taxonomy derived from risk level + attack type."""

from __future__ import annotations

from enum import Enum
from typing import Final


class FinalStatus(str, Enum):
    """Unified operational status for the SOC dashboard."""

    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    UNDER_INVESTIGATION = "Under Investigation"
    CONFIRMED_THREAT = "Confirmed Threat"


VALID_FINAL_STATUSES: Final[frozenset[str]] = frozenset(
    status.value for status in FinalStatus
)

NORMAL_ATTACK_TYPE: Final[str] = "Normal Activity"

# Labels that mean "no signature rule matched" (cannot become Confirmed Threat).
NON_SIGNATURE_ATTACK_TYPES: Final[frozenset[str]] = frozenset(
    {
        "None",
        "Behavioural Anomaly",
        "Unknown Behaviour",
        "Normal Activity",  # legacy
        "",
    }
)

# Ambiguous / FP-tuning labels: classified for analysts but never auto-confirmed.
EDGE_CASE_ATTACK_TYPES: Final[frozenset[str]] = frozenset(
    {
        "Insider Drift",
    }
)


def is_signature_attack(attack_type: str | None) -> bool:
    """True when a named attack rule matched (not None / Behavioural Anomaly)."""
    label = (attack_type or "").strip()
    return bool(label) and label not in NON_SIGNATURE_ATTACK_TYPES


def is_confirmable_attack(attack_type: str | None) -> bool:
    """True when a signature match is eligible for Confirmed Threat status."""
    label = (attack_type or "").strip()
    return is_signature_attack(label) and label not in EDGE_CASE_ATTACK_TYPES
