"""Employee hierarchy generator."""

from __future__ import annotations

from collections.abc import Sequence
import re

from faker import Faker

from synthetic_data.config import (
    DEFAULT_WORK_END_HOUR,
    DEFAULT_WORK_START_HOUR,
    DEPARTMENT_IC_ROLES,
    DIRECTOR_ROLE,
    COMPANY_EMAIL_DOMAIN,
    MANAGER_ROLE,
    MAX_EMPLOYEES_PER_MANAGER,
    MAX_MANAGERS_PER_DIRECTOR,
    MIN_EMPLOYEES_PER_MANAGER,
    MIN_MANAGERS_PER_DIRECTOR,
    NUMBER_OF_EMPLOYEES,
)
from synthetic_data.models import Department, Employee, Location


def _slugify_name(full_name: str) -> str:
    """Convert a person name into an email-local-part fragment."""
    cleaned = re.sub(r"[^a-zA-Z0-9]+", ".", full_name.strip().lower())
    return cleaned.strip(".")


def _distribute_headcount(total: int, buckets: int) -> list[int]:
    """Split ``total`` people across ``buckets`` as evenly as possible."""
    if buckets <= 0:
        raise ValueError("buckets must be a positive integer")
    if total < buckets:
        raise ValueError(
            f"Cannot place {total} employees into {buckets} departments "
            "(need at least one person per department for a Director)"
        )

    base, remainder = divmod(total, buckets)
    return [base + (1 if index < remainder else 0) for index in range(buckets)]


def _plan_manager_team_sizes(remaining_seats: int) -> list[int]:
    """Plan IC headcount per manager for seats left after the Director.

    Prefers ``MIN_MANAGERS_PER_DIRECTOR``–``MAX_MANAGERS_PER_DIRECTOR`` managers
    and ``MIN_EMPLOYEES_PER_MANAGER``–``MAX_EMPLOYEES_PER_MANAGER`` reports.
    Relaxes those bounds only when the configured department size cannot
    satisfy them exactly (for example, total company size below the ideal
    minimum).

    Args:
        remaining_seats: People in the department excluding the Director.
            This pool includes both Managers and their IC reports.

    Returns:
        A list where each entry is the number of IC employees under one
        manager. The list length is the manager count. Empty when the
        department is Director-only.
    """
    if remaining_seats <= 0:
        return []

    preferred_min_m = MIN_MANAGERS_PER_DIRECTOR
    preferred_max_m = MAX_MANAGERS_PER_DIRECTOR
    min_ic = MIN_EMPLOYEES_PER_MANAGER
    max_ic = MAX_EMPLOYEES_PER_MANAGER

    best: tuple[float, list[int]] | None = None

    for manager_count in range(1, remaining_seats + 1):
        ic_total = remaining_seats - manager_count
        if ic_total < 0:
            continue

        base, extra = divmod(ic_total, manager_count)
        team_sizes = [base + (1 if i < extra else 0) for i in range(manager_count)]

        # Score: reward preferred hierarchy bounds; lightly penalize outliers.
        score = 0.0
        if preferred_min_m <= manager_count <= preferred_max_m:
            score += 25.0
        else:
            score -= abs(manager_count - min(preferred_max_m, max(preferred_min_m, manager_count))) * 5.0

        for size in team_sizes:
            if min_ic <= size <= max_ic:
                score += 3.0
            elif size == 0:
                score -= 8.0
            else:
                target = min(max_ic, max(min_ic, size))
                score -= abs(size - target) * 1.5

        if best is None or score > best[0]:
            best = (score, team_sizes)

    assert best is not None
    return best[1]


def _unique_email(full_name: str, used: set[str], domain: str, faker: Faker) -> str:
    """Create a unique corporate email for an employee."""
    local = _slugify_name(full_name) or "employee"
    candidate = f"{local}@{domain}"
    suffix = 1
    while candidate in used:
        candidate = f"{local}{suffix}@{domain}"
        suffix += 1
        if suffix > 10_000:
            # Extremely unlikely fallback using Faker for uniqueness.
            candidate = f"{faker.user_name()}{suffix}@{domain}"
    used.add(candidate)
    return candidate


def _pick_office(locations: Sequence[Location], faker: Faker) -> Location:
    """Select a random office location for an employee."""
    return faker.random.choice(list(locations))


def _pick_ic_role(department_name: str, faker: Faker) -> str:
    """Select an individual-contributor role for a department."""
    roles = DEPARTMENT_IC_ROLES.get(department_name)
    if not roles:
        return "Intern"
    return faker.random.choice(roles)


def _build_employee(
    *,
    employee_id: str,
    full_name: str,
    email: str,
    department: Department,
    role: str,
    manager_id: str | None,
    office: Location,
) -> Employee:
    """Construct an Employee entity with location-derived timezone."""
    return Employee(
        employee_id=employee_id,
        full_name=full_name,
        email=email,
        department_id=department.department_id,
        role=role,
        manager_id=manager_id,
        office_location_id=office.location_id,
        timezone=office.timezone,
        work_start_hour=DEFAULT_WORK_START_HOUR,
        work_end_hour=DEFAULT_WORK_END_HOUR,
        assigned_device_ids=[],
    )


def generate_employees(
    departments: Sequence[Department],
    locations: Sequence[Location],
    number_of_employees: int | None = None,
    *,
    faker: Faker | None = None,
    email_domain: str = COMPANY_EMAIL_DOMAIN,
) -> list[Employee]:
    """Generate a hierarchical workforce for the enterprise.

    Hierarchy rules:
        * Each department has exactly one Director (no manager).
        * Each Director manages a set of Managers (same department).
        * Each Manager manages a set of IC employees (same department).
        * Every non-Director employee has exactly one manager.

    Args:
        departments: Departments to staff.
        locations: Office locations used for ``office_location_id`` / timezone.
        number_of_employees: Total headcount. Defaults to
            ``config.NUMBER_OF_EMPLOYEES``. Never hardcoded in this module.
        faker: Optional Faker instance (shares RNG with the company generator).
        email_domain: Corporate email domain.

    Returns:
        Employees across all departments. Length equals ``number_of_employees``.
    """
    if not departments:
        raise ValueError("departments must not be empty")
    if not locations:
        raise ValueError("locations must not be empty")

    total = NUMBER_OF_EMPLOYEES if number_of_employees is None else number_of_employees
    if total <= 0:
        raise ValueError("number_of_employees must be a positive integer")

    fake = faker or Faker()
    dept_sizes = _distribute_headcount(total, len(departments))

    employees: list[Employee] = []
    used_emails: set[str] = set()
    next_index = 1

    for department, dept_size in zip(departments, dept_sizes, strict=True):
        team_sizes = _plan_manager_team_sizes(dept_size - 1)
        manager_count = len(team_sizes)

        # Director
        director_name = fake.name()
        director_id = f"EMP-{next_index:04d}"
        next_index += 1
        director_office = _pick_office(locations, fake)
        director = _build_employee(
            employee_id=director_id,
            full_name=director_name,
            email=_unique_email(director_name, used_emails, email_domain, fake),
            department=department,
            role=DIRECTOR_ROLE,
            manager_id=None,
            office=director_office,
        )
        employees.append(director)

        # Managers (report to Director)
        manager_ids: list[str] = []
        for _ in range(manager_count):
            manager_name = fake.name()
            manager_id = f"EMP-{next_index:04d}"
            next_index += 1
            manager_office = _pick_office(locations, fake)
            manager = _build_employee(
                employee_id=manager_id,
                full_name=manager_name,
                email=_unique_email(manager_name, used_emails, email_domain, fake),
                department=department,
                role=MANAGER_ROLE,
                manager_id=director.employee_id,
                office=manager_office,
            )
            employees.append(manager)
            manager_ids.append(manager_id)

        # IC employees (report to a Manager in the same department)
        for manager_id, ic_count in zip(manager_ids, team_sizes, strict=True):
            for _ in range(ic_count):
                person_name = fake.name()
                employee_id = f"EMP-{next_index:04d}"
                next_index += 1
                office = _pick_office(locations, fake)
                employee = _build_employee(
                    employee_id=employee_id,
                    full_name=person_name,
                    email=_unique_email(person_name, used_emails, email_domain, fake),
                    department=department,
                    role=_pick_ic_role(department.name, fake),
                    manager_id=manager_id,
                    office=office,
                )
                employees.append(employee)

    if len(employees) != total:
        raise RuntimeError(
            f"Employee generator produced {len(employees)} people; expected {total}"
        )

    return employees
