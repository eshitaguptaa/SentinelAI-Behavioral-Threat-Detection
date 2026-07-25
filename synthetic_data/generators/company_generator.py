"""Company-level enterprise structure orchestrator."""

from __future__ import annotations

from faker import Faker

from synthetic_data.config import (
    COMPANY_EMAIL_DOMAIN,
    DEVICE_PROBABILITIES,
    NUMBER_OF_EMPLOYEES,
    NUMBER_OF_LOCATIONS,
    RANDOM_SEED,
)
from synthetic_data.generators.department_generator import generate_departments
from synthetic_data.generators.device_generator import generate_devices
from synthetic_data.generators.employee_generator import generate_employees
from synthetic_data.generators.location_generator import generate_locations
from synthetic_data.generators.resource_generator import generate_resources
from synthetic_data.models.enterprise import Enterprise


def generate_enterprise(
    *,
    number_of_employees: int | None = None,
    number_of_locations: int | None = None,
    device_probabilities: dict[str, float] | None = None,
    email_domain: str = COMPANY_EMAIL_DOMAIN,
    seed: int | None = RANDOM_SEED,
) -> Enterprise:
    """Build a complete in-memory enterprise structure.

    This orchestrator composes independent generators and returns a single
    ``Enterprise`` aggregate. It does **not** generate login events, user
    behavior, attacks, or files on disk.

    Args:
        number_of_employees: Total workforce size. Defaults to
            ``config.NUMBER_OF_EMPLOYEES``.
        number_of_locations: Office count. Defaults to
            ``config.NUMBER_OF_LOCATIONS``.
        device_probabilities: Optional override for device assignment rates.
        email_domain: Corporate email domain for generated employees.
        seed: Optional Faker/Random seed for reproducible structure.

    Returns:
        Enterprise containing departments, locations, employees, devices,
        and resources.
    """
    employee_count = (
        NUMBER_OF_EMPLOYEES if number_of_employees is None else number_of_employees
    )
    location_count = (
        NUMBER_OF_LOCATIONS if number_of_locations is None else number_of_locations
    )
    probabilities = (
        DEVICE_PROBABILITIES if device_probabilities is None else device_probabilities
    )

    if seed is not None:
        Faker.seed(seed)
    faker = Faker()
    if seed is not None:
        faker.seed_instance(seed)

    departments = generate_departments()
    locations = generate_locations(count=location_count)
    employees = generate_employees(
        departments=departments,
        locations=locations,
        number_of_employees=employee_count,
        faker=faker,
        email_domain=email_domain,
    )
    devices = generate_devices(
        employees=employees,
        probabilities=probabilities,
        faker=faker,
    )
    resources = generate_resources(departments=departments)

    return Enterprise(
        departments=departments,
        locations=locations,
        employees=employees,
        devices=devices,
        resources=resources,
    )
