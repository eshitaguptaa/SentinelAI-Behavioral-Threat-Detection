"""MITRE ATT&CK mapping for rule-based attack classification labels."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class MitreMapping:
    """ATT&CK tactic/technique pair for a detected attack label."""

    attack_type: str
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    description: str


_MITRE_BY_ATTACK: Final[dict[str, MitreMapping]] = {
    "Impossible Travel": MitreMapping(
        attack_type="Impossible Travel",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1078",
        technique_name="Valid Accounts",
        description="Authenticated activity from geographically implausible locations.",
    ),
    "Brute Force": MitreMapping(
        attack_type="Brute Force",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        description="Repeated authentication failures consistent with password guessing.",
    ),
    "Credential Stuffing": MitreMapping(
        attack_type="Credential Stuffing",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1110.004",
        technique_name="Credential Stuffing",
        description="High-volume login attempts indicative of reused credential spraying.",
    ),
    "Device Spoofing": MitreMapping(
        attack_type="Device Spoofing",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1200",
        technique_name="Hardware Additions",
        description="Activity from untrusted or suddenly changing device fingerprints.",
    ),
    "Lateral Movement": MitreMapping(
        attack_type="Lateral Movement",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        description="Host-to-host pivoting via SSH, RDP, or remote admin channels.",
    ),
    "Insider Activity": MitreMapping(
        attack_type="Insider Activity",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        technique_id="T1052",
        technique_name="Exfiltration Over Physical Medium",
        description="Sensitive reads followed by removable-media or bulk transfer signals.",
    ),
    "Mass Download": MitreMapping(
        attack_type="Mass Download",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        technique_id="T1030",
        technique_name="Data Transfer Size Limits",
        description="Abnormally large file download volume for the employee baseline.",
    ),
    "Suspicious VPN Usage": MitreMapping(
        attack_type="Suspicious VPN Usage",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        technique_id="T1572",
        technique_name="Protocol Tunneling",
        description="VPN patterns inconsistent with the employee's normal access posture.",
    ),
}


def map_attack_to_mitre(attack_type: str) -> MitreMapping | None:
    """Return MITRE mapping for a classified attack, or ``None`` for Normal Activity."""
    if attack_type == "Normal Activity":
        return None
    return _MITRE_BY_ATTACK.get(attack_type)


def mitre_dict(attack_type: str) -> dict[str, str] | None:
    """JSON-serializable MITRE mapping for API responses."""
    mapping = map_attack_to_mitre(attack_type)
    if mapping is None:
        return None
    return {
        "attack_type": mapping.attack_type,
        "tactic_id": mapping.tactic_id,
        "tactic_name": mapping.tactic_name,
        "technique_id": mapping.technique_id,
        "technique_name": mapping.technique_name,
        "description": mapping.description,
    }
