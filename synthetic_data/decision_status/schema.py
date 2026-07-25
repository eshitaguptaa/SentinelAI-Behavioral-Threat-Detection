"""Final SOC status taxonomy derived from risk level + attack type."""

from __future__ import annotations

from enum import Enum
from typing import Final


class FinalStatus(str, Enum):
    """Unified operational status for the SOC dashboard."""

    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    CONFIRMED_THREAT = "Confirmed Threat"


VALID_FINAL_STATUSES: Final[frozenset[str]] = frozenset(
    status.value for status in FinalStatus
)

NORMAL_ATTACK_TYPE: Final[str] = "Normal Activity"
