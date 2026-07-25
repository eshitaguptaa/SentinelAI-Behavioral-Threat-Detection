"""Device domain model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Device:
    """Endpoint used by an employee to access corporate resources.

    Attributes:
        device_id: Stable unique identifier for the device.
        owner_id: Identifier of the employee who owns or is assigned the device.
        device_type: Device class (for example: laptop, desktop, mobile).
        operating_system: OS family/version string.
        browser: Primary browser used on the device, if applicable.
        trusted: Whether the device is considered a trusted corporate asset.
        mac_address: Hardware MAC address when available.
    """

    device_id: str
    owner_id: str
    device_type: str = "laptop"
    operating_system: str = "unknown"
    browser: str | None = None
    trusted: bool = True
    mac_address: str | None = None
