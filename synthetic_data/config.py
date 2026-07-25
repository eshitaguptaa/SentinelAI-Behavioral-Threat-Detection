"""Configuration for SentinelAI enterprise structure generation.

All generator sizing and probability knobs live here so headcounts and
device assignment rates can be changed without touching generator code.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Scale
# ---------------------------------------------------------------------------

NUMBER_OF_EMPLOYEES: int = 100
NUMBER_OF_LOCATIONS: int = 5
NUMBER_OF_SIMULATION_DAYS: int = 30

# ---------------------------------------------------------------------------
# Device assignment probabilities (0.0 – 1.0)
# ---------------------------------------------------------------------------

DEVICE_PROBABILITIES: dict[str, float] = {
    "laptop": 1.0,  # every employee receives a laptop
    "mobile": 0.70,
    "tablet": 0.25,
}

# ---------------------------------------------------------------------------
# Identity / reproducibility
# ---------------------------------------------------------------------------

COMPANY_EMAIL_DOMAIN: str = "sentinelai.corp"
RANDOM_SEED: int | None = 42

# ---------------------------------------------------------------------------
# Departments (name -> sensitivity)
# ---------------------------------------------------------------------------

DEPARTMENT_DEFINITIONS: Final[list[tuple[str, str]]] = [
    ("Engineering", "Medium"),
    ("IT", "High"),
    ("Finance", "Critical"),
    ("Human Resources", "High"),
    ("Sales", "Medium"),
    ("Marketing", "Low"),
    ("Legal", "Critical"),
    ("Operations", "Medium"),
]

# ---------------------------------------------------------------------------
# Office locations (city, country, latitude, longitude, timezone)
# ---------------------------------------------------------------------------

OFFICE_LOCATION_DEFINITIONS: Final[
    list[tuple[str, str, float, float, str]]
] = [
    ("Bengaluru", "India", 12.9716, 77.5946, "Asia/Kolkata"),
    ("Hyderabad", "India", 17.3850, 78.4867, "Asia/Kolkata"),
    ("London", "United Kingdom", 51.5074, -0.1278, "Europe/London"),
    ("New York", "United States", 40.7128, -74.0060, "America/New_York"),
    ("Singapore", "Singapore", 1.3521, 103.8198, "Asia/Singapore"),
]

# ---------------------------------------------------------------------------
# Hierarchy bounds (Director → Managers → Employees)
# ---------------------------------------------------------------------------

MIN_MANAGERS_PER_DIRECTOR: int = 2
MAX_MANAGERS_PER_DIRECTOR: int = 5
MIN_EMPLOYEES_PER_MANAGER: int = 5
MAX_EMPLOYEES_PER_MANAGER: int = 15

# ---------------------------------------------------------------------------
# Role catalog
# ---------------------------------------------------------------------------

DIRECTOR_ROLE: str = "Director"
MANAGER_ROLE: str = "Manager"

DEPARTMENT_IC_ROLES: Final[dict[str, list[str]]] = {
    "Engineering": ["Software Engineer", "Senior Engineer", "Intern"],
    "IT": ["Security Analyst", "Intern"],
    "Finance": ["Finance Analyst", "Intern"],
    "Human Resources": ["HR Executive", "Intern"],
    "Sales": ["Sales Executive", "Intern"],
    "Marketing": ["Marketing Executive", "Intern"],
    "Legal": ["Legal Counsel", "Intern"],
    "Operations": ["Operations Engineer", "Intern"],
}

# ---------------------------------------------------------------------------
# Device catalogs
# ---------------------------------------------------------------------------

OPERATING_SYSTEMS: Final[list[str]] = ["Windows", "macOS", "Linux"]

BROWSERS_BY_OS: Final[dict[str, list[str]]] = {
    "Windows": ["Chrome", "Edge", "Firefox"],
    "macOS": ["Chrome", "Safari", "Firefox"],
    "Linux": ["Chrome", "Firefox"],
}

# ---------------------------------------------------------------------------
# Work-hour defaults (local 24-hour clock)
# ---------------------------------------------------------------------------

DEFAULT_WORK_START_HOUR: int = 9
DEFAULT_WORK_END_HOUR: int = 17
