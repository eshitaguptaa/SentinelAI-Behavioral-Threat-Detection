"""Plugin registry for attack-technique injectors.

Each technique lives in its own module and exposes ``inject(...)``.
The Attack Injection Engine registers these callables automatically.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from synthetic_data.attack_types import AttackType

from . import (
    after_hours,
    brute_force,
    credential_theft,
    data_exfiltration,
    device_spoofing,
    impossible_travel,
    insider_drift,
    lateral_movement,
    low_and_slow,
    privilege_escalation,
)

TechniqueInjector = Callable[..., tuple[Any, Any]]

TECHNIQUE_INJECTORS: dict[AttackType, TechniqueInjector] = {
    AttackType.IMPOSSIBLE_TRAVEL: impossible_travel.inject,
    AttackType.CREDENTIAL_THEFT: credential_theft.inject,
    AttackType.PRIVILEGE_ESCALATION: privilege_escalation.inject,
    AttackType.DATA_EXFILTRATION: data_exfiltration.inject,
    AttackType.AFTER_HOURS_ACCESS: after_hours.inject,
    AttackType.LATERAL_MOVEMENT: lateral_movement.inject,
    AttackType.BRUTE_FORCE_LOGIN: brute_force.inject,
    AttackType.DEVICE_SPOOFING: device_spoofing.inject,
    AttackType.LOW_AND_SLOW_EXFIL: low_and_slow.inject,
    AttackType.INSIDER_DRIFT: insider_drift.inject,
}


def get_default_injectors() -> dict[AttackType, TechniqueInjector]:
    """Return a fresh copy of the default technique → injector mapping."""
    return dict(TECHNIQUE_INJECTORS)


__all__ = [
    "TECHNIQUE_INJECTORS",
    "TechniqueInjector",
    "get_default_injectors",
]
