"""Realistic attack event-type sequences that blend with normal behaviour."""

from __future__ import annotations

from typing import Final

# Sequences used by generators / demos / evaluation — not ML labels.
CREDENTIAL_THEFT_SEQUENCE: Final[tuple[str, ...]] = (
    "FAILED_LOGIN",
    "FAILED_LOGIN",
    "LOGIN",
    "PASSWORD_CHANGE",
    "EMAIL_ACCESS",
    "FILE_DOWNLOAD",
    "LOGOUT",
)

INSIDER_THREAT_SEQUENCE: Final[tuple[str, ...]] = (
    "LOGIN",
    "FILE_READ",
    "FILE_DOWNLOAD",
    "USB_INSERT",
    "LOGOUT",
)

PRIVILEGE_ESCALATION_SEQUENCE: Final[tuple[str, ...]] = (
    "LOGIN",
    "ADMIN_LOGIN",
    "POLICY_CHANGE",
    "DATABASE_ACCESS",
)

LATERAL_MOVEMENT_SEQUENCE: Final[tuple[str, ...]] = (
    "LOGIN",
    "SSH_LOGIN",
    "REMOTE_DESKTOP",
    "DATABASE_ACCESS",
)

BRUTE_FORCE_SEQUENCE: Final[tuple[str, ...]] = (
    "FAILED_LOGIN",
    "FAILED_LOGIN",
    "FAILED_LOGIN",
    "FAILED_LOGIN",
    "FAILED_LOGIN",
    "LOGIN",
    "EMAIL_ACCESS",
    "LOGOUT",
)

DATA_EXFILTRATION_SEQUENCE: Final[tuple[str, ...]] = (
    "LOGIN",
    "FILE_READ",
    "FILE_READ",
    "FILE_DOWNLOAD",
    "FILE_UPLOAD",
    "VPN_DISCONNECT",
    "LOGOUT",
)

ATTACK_SEQUENCE_CATALOG: Final[dict[str, tuple[str, ...]]] = {
    "Credential Theft": CREDENTIAL_THEFT_SEQUENCE,
    "Insider Threat": INSIDER_THREAT_SEQUENCE,
    "Privilege Escalation": PRIVILEGE_ESCALATION_SEQUENCE,
    "Lateral Movement": LATERAL_MOVEMENT_SEQUENCE,
    "Brute Force": BRUTE_FORCE_SEQUENCE,
    "Data Exfiltration": DATA_EXFILTRATION_SEQUENCE,
}


def blend_attack_into_session(
    normal_events: list[str],
    attack_events: tuple[str, ...] | list[str],
    *,
    insert_after: int = 2,
) -> list[str]:
    """Insert an attack subsequence into a normal session skeleton."""
    if not normal_events:
        return list(attack_events)
    index = max(1, min(insert_after, len(normal_events) - 1))
    return list(normal_events[:index]) + list(attack_events) + list(normal_events[index:])
