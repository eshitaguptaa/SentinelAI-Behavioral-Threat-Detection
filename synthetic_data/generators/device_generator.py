"""Trusted device generator for enterprise employees."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from faker import Faker

from synthetic_data.config import (
    BROWSERS_BY_OS,
    DEVICE_PROBABILITIES,
    OPERATING_SYSTEMS,
)
from synthetic_data.models import Device, Employee


def _mac_address(faker: Faker) -> str:
    """Generate a realistic locally-administered unicast MAC address."""
    octets = [faker.random.randint(0x00, 0xFF) for _ in range(6)]
    # Force locally administered (bit 1) and unicast (bit 0 cleared).
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{value:02X}" for value in octets)


def _choose_os_and_browser(device_type: str, faker: Faker) -> tuple[str, str]:
    """Pick a plausible OS/browser pair for a device type."""
    if device_type == "mobile":
        operating_system = faker.random.choice(["Android", "iOS"])
        browser = faker.random.choice(["Chrome", "Safari"])
        return operating_system, browser

    if device_type == "tablet":
        operating_system = faker.random.choice(["iPadOS", "Android", "Windows"])
        browser = faker.random.choice(["Safari", "Chrome", "Edge"])
        return operating_system, browser

    operating_system = faker.random.choice(list(OPERATING_SYSTEMS))
    browsers = BROWSERS_BY_OS.get(operating_system, ["Chrome"])
    browser = faker.random.choice(browsers)
    return operating_system, browser


def generate_devices(
    employees: Sequence[Employee],
    *,
    probabilities: Mapping[str, float] | None = None,
    faker: Faker | None = None,
) -> list[Device]:
    """Assign trusted devices to employees.

    Rules:
        * Every employee receives a laptop (probability defaults to 1.0).
        * Mobile and tablet devices are assigned independently using
          ``DEVICE_PROBABILITIES``.
        * All generated devices are marked ``trusted=True``.
        * Each employee's ``assigned_device_ids`` is updated in place.

    Args:
        employees: Workforce that will own the devices.
        probabilities: Optional override for device-type probabilities.
        faker: Optional Faker instance for shared RNG.

    Returns:
        All generated Device entities.
    """
    fake = faker or Faker()
    probs = dict(DEVICE_PROBABILITIES if probabilities is None else probabilities)

    laptop_probability = float(probs.get("laptop", 1.0))
    mobile_probability = float(probs.get("mobile", 0.0))
    tablet_probability = float(probs.get("tablet", 0.0))

    devices: list[Device] = []
    next_index = 1

    for employee in employees:
        assigned: list[str] = []

        device_plan: list[str] = []
        if fake.random.random() < laptop_probability:
            device_plan.append("laptop")
        if fake.random.random() < mobile_probability:
            device_plan.append("mobile")
        if fake.random.random() < tablet_probability:
            device_plan.append("tablet")

        # Guarantee a laptop even if probability config is mis-set.
        if "laptop" not in device_plan:
            device_plan.insert(0, "laptop")

        for device_type in device_plan:
            device_id = f"DEV-{next_index:04d}"
            next_index += 1
            operating_system, browser = _choose_os_and_browser(device_type, fake)
            device = Device(
                device_id=device_id,
                owner_id=employee.employee_id,
                device_type=device_type,
                operating_system=operating_system,
                browser=browser,
                trusted=True,
                mac_address=_mac_address(fake),
            )
            devices.append(device)
            assigned.append(device_id)

        employee.assigned_device_ids = assigned

    return devices
