"""Attack classification schema for SentinelAI.

Rule-based labels produced after the Risk Engine. Never uses Isolation Forest
weights or attack ground-truth simulator fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class AttackType(str, Enum):
    """Supported deterministic attack / activity classifications."""

    IMPOSSIBLE_TRAVEL = "Impossible Travel"
    BRUTE_FORCE = "Brute Force"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    DEVICE_SPOOFING = "Device Spoofing"
    LATERAL_MOVEMENT = "Lateral Movement"
    INSIDER_ACTIVITY = "Insider Activity"
    MASS_DOWNLOAD = "Mass Download"
    SUSPICIOUS_VPN_USAGE = "Suspicious VPN Usage"
    # Non-signature labels (no attack rule matched):
    NONE = "None"
    BEHAVIOURAL_ANOMALY = "Behavioural Anomaly"
    UNKNOWN_BEHAVIOUR = "Unknown Behaviour"
    # Legacy — retained for older fixtures; never emitted by the classifier.
    NORMAL_ACTIVITY = "Normal Activity"


VALID_ATTACK_TYPES: Final[frozenset[str]] = frozenset(
    attack.value for attack in AttackType
)

# Behavioural fields the classifier is allowed to read (ml_features subset).
ALLOWED_CLASSIFICATION_FEATURES: Final[frozenset[str]] = frozenset(
    {
        "country_change_count",
        "auth_failure_rate",
        "max_failed_login_streak",
        "login_count",
        "download_size_mb_sum",
        "mass_download_event_count",
        "unique_device_count",
        "device_entropy",
        "after_hours_event_count",
        "active_duration_hours",
        "file_access_ratio",
        "vpn_usage_ratio",
        "unique_location_count",
        "location_change_count",
    }
)


@dataclass(slots=True)
class AttackClassification:
    """Deterministic attack classification for one employee-day.

    Attributes:
        employee_id: Employee identifier.
        simulation_day: ISO simulation day.
        attack_type: Human-readable attack / activity label.
        attack_confidence: Confidence in ``[0.0, 1.0]``.
        matched_signals: Behavioural signals that fired for this label.
    """

    employee_id: str
    simulation_day: str
    attack_type: str
    attack_confidence: float
    matched_signals: list[str]
